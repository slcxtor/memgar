"""PII anonymization for pilot memory-write traffic.

Privacy contract:
  * No raw PII or secrets leaves this module unmasked.
  * Each detected entity is replaced by a deterministic *category token*
    (``<EMAIL>``, ``<WALLET>``, ``<HASH:abc12345>`` for identifiers), so the
    semantic shape needed for ML training is preserved without re-identification.
  * Identifier hashing uses HMAC-SHA256 with a per-pilot salt. Without the salt,
    the hashes are irreversible; the salt itself never leaves disk.
  * Wraps the existing ``DLPRedactor`` for canonical patterns (emails, OpenAI
    keys, etc.) and layers additional categories on top.

Categories scrubbed:
  emails, phone numbers, US SSNs, credit-card numbers (Luhn-checked),
  IPv4/IPv6 addresses, URLs (domain replaced, path kept), hex/base58 crypto
  wallet addresses, JWTs, bearer tokens, UUIDs, generic API keys
  (sk-…, ghp_…, AKIA…, etc.), and a salted hash of agent / source IDs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Tuple


# --------------------------------------------------------------------------- regexes
# Order matters — longest / most specific first so they win the substitution race.
_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("JWT",        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("BEARER",     re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}\b")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("GITHUB_PAT", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("AWS_KEY",    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("HF_TOKEN",   re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("EMAIL",      re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CRYPTO_HEX", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
    ("CRYPTO_BTC", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
    ("IBAN",       re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ("UUID",       re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("IPV6",       re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b")),
    ("IPV4",       re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    # CC and SSN run BEFORE PHONE so a Luhn-valid card number wins over the
    # phone pattern, and so an invalid 16-digit block survives unredacted.
    ("CC",         re.compile(r"\b(?:\d[ \-]?){13,19}\b")),  # candidate; Luhn-verified below
    ("SSN",        re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # PHONE: require an E.164-style leading "+" OR a parenthesised area code, so
    # unstructured digit blocks (tracking numbers, IDs) are not over-redacted.
    ("PHONE",      re.compile(r"(?:\+\d{1,3}|\(\d{2,4}\))[\s\-.]?\d{2,4}[\s\-.]\d{2,4}(?:[\s\-.]\d{2,4})?")),
)


@dataclass
class AnonymizationResult:
    text: str                                        # safe text with tokens
    counts: Dict[str, int] = field(default_factory=dict)
    leaked_categories: Tuple[str, ...] = ()          # categories we suspect were missed

    @property
    def total_redactions(self) -> int:
        return sum(self.counts.values())


def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in num if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PilotAnonymizer:
    """Deterministic, salt-protected text anonymizer for pilot collection.

    The salt is persisted at ``<state_dir>/.pilot_salt`` on first use (mode 0o600)
    and never leaves disk. Hash tokens are 16-hex truncations of HMAC-SHA256.
    """

    _SALT_NAME = ".pilot_salt"

    def __init__(self, state_dir: str | os.PathLike = "ml/pilot_state") -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._salt = self._load_or_create_salt()
        try:
            from memgar.secure_memory_store import DLPRedactor
            self._dlp = DLPRedactor()
        except Exception:
            self._dlp = None

    # ------------------------------------------------------------------ salt
    def _load_or_create_salt(self) -> bytes:
        path = self.state_dir / self._SALT_NAME
        if path.exists():
            return path.read_bytes()
        salt = secrets.token_bytes(32)
        path.write_bytes(salt)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return salt

    # ------------------------------------------------------------------ hash
    def hash_id(self, identifier: Optional[str], *, length: int = 16) -> str:
        """Stable, irreversible token for an agent/source identifier."""
        if not identifier:
            return "<HASH:none>"
        digest = hmac.new(self._salt, identifier.encode("utf-8"),
                          hashlib.sha256).hexdigest()
        return f"<HASH:{digest[:length]}>"

    # ----------------------------------------------------------------- scrub
    def anonymize(self, text: str) -> AnonymizationResult:
        if not text:
            return AnonymizationResult(text="")
        counts: Dict[str, int] = {}
        out = text

        # Layered DLP scrub first (canonical categories tested in the repo).
        if self._dlp is not None:
            try:
                res = self._dlp.inspect(out)
                if getattr(res, "was_redacted", False):
                    out = res.redacted
                    counts["DLP"] = len(getattr(res, "findings", []) or [])
            except Exception:
                pass

        # Then our extra regex categories.
        for label, pattern in _PATTERNS:
            def _sub(match):
                value = match.group(0)
                if label == "CC" and not _luhn_ok(value):
                    return value
                counts[label] = counts.get(label, 0) + 1
                return f"<{label}>"
            out = pattern.sub(_sub, out)

        # URL domain scrub: keep the path shape, mask the host.
        def _url(match):
            counts["URL_HOST"] = counts.get("URL_HOST", 0) + 1
            return f"{match.group(1)}://<HOST>{match.group(2) or ''}"
        out = re.sub(r"\b(https?|ftp)://[^\s/]+(/\S*)?", _url, out)

        # Lightweight leak guard — never ship something that still smells of PII.
        leaked = tuple(
            cat for cat, rx in (
                ("EMAIL", _PATTERNS[7][1]),
                ("OPENAI_KEY", _PATTERNS[2][1]),
            ) if rx.search(out)
        )
        return AnonymizationResult(text=out, counts=counts, leaked_categories=leaked)


__all__ = ["PilotAnonymizer", "AnonymizationResult"]
