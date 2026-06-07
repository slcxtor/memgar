"""Per-tenant continuous learning for Memgar.

Lets a deployment teach Memgar what's benign in *its* domain without modifying
global patterns. A hospital can mark "cross-reference patient charts" as
benign; a customer-support deployment can mark "forward all tickets to
internal-archive.local" as benign — these only affect that tenant, never
others, and are gated to prevent feedback poisoning.

Design principles
-----------------
1. **Tenant isolation.** State lives under ``storage/tenants/<tenant_id>/``.
   Tenant A's allowlist never affects tenant B.
2. **Anti-poisoning.** An attacker who controls feedback for one tenant must
   not be able to whitelist real attacks. We refuse to mark-as-benign any
   content that hits a CRITICAL severity pattern, rate-limit markings, cap
   the per-tenant store size, and record provenance.
3. **Soft dampen, never bypass.** Tenant whitelist *reduces* risk score; it
   does not override CRITICAL findings. A high-severity Layer-1 hit always
   wins — the worst case for tenant feedback is a borderline benign-marked
   item is no longer quarantined for that tenant.
4. **Quality gate stays.** No global model or pattern is ever changed by
   tenant feedback. The gold gate FPR / recall remain measurable and pinned.
5. **Optional.** Off by default. Opt in via ``Analyzer(tenant_learning=True)``.

Storage layout::

    storage/tenants/<tenant_id>/
        policy.json          # metadata + counts
        benigns.jsonl        # one row per marked-benign entry
        attacks.jsonl        # one row per customer-flagged missed attack
        audit.jsonl          # who marked what when (immutable log)

The benign matcher uses normalised SHA256 for exact dedup, plus optional
sentence-transformer cosine similarity (re-using ``SimilarityLayer``'s
encoder so the model is loaded once).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Default storage root; overridable via MEMGAR_TENANT_STORE env var.
def _default_store_root() -> Path:
    import os
    root = os.environ.get("MEMGAR_TENANT_STORE")
    if root:
        return Path(root).expanduser().resolve()
    return Path.home() / ".memgar" / "tenant_learning"


def _normalise(text: str) -> str:
    """Cheap normalisation for hash-based dedup: lowercase, collapse
    whitespace, strip punctuation at the edges. Intentionally loose so
    "Forward my receipts." and "forward my receipts" hash the same."""
    if not text:
        return ""
    t = text.lower().strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"^[\W_]+|[\W_]+$", "", t)
    return t


def _content_hash(text: str) -> str:
    return hashlib.sha256(_normalise(text).encode("utf-8")).hexdigest()[:32]


# --- Anti-poisoning constants -----------------------------------------------
# These are deliberately conservative defaults. A tenant operator who needs
# different limits can subclass TenantLearningStore.

# Max number of benign entries kept per tenant. Beyond this, oldest is
# evicted (LRU). 10k is enough for a year of an active deployment without
# blowing up memory; sentence-transformer embeddings at 384-d float32 use
# ~15 KB each → ~150 MB per tenant at the cap.
MAX_BENIGNS_PER_TENANT = 10_000

# Max number of markings (benign or attack) accepted per tenant per minute.
# Higher than human-rate to allow batch onboarding, low enough to make
# automated poisoning expensive.
MAX_MARKINGS_PER_MINUTE = 60

# Similarity score below which an existing benign match contributes nothing.
# Above this, the dampen amount scales linearly up to MAX_DAMPEN at sim=1.0.
SIM_DAMPEN_FLOOR = 0.85
MAX_DAMPEN = 25  # never reduce risk below threats' intrinsic floor

# Decision floor: even with full dampen, NEVER allow content that hit a
# CRITICAL severity threat or whose un-dampened risk_score was ≥ this.
CRITICAL_RISK_FLOOR = 80


# ============================================================================
# Data models
# ============================================================================

@dataclass
class BenignRecord:
    """One marked-benign entry in a tenant's allowlist."""
    content_hash: str
    text_preview: str   # first 120 chars; full text NOT stored
    reason: str
    marked_by: str       # operator / system identifier
    marked_at: float     # unix ts
    use_count: int = 0
    last_used_at: float = 0.0
    # Embedding is held in-memory only (rebuilt from text_preview on load
    # if SimilarityLayer is available). Not serialised → keeps disk small.


@dataclass
class MarkAttackRecord:
    """A customer flag that memgar missed an attack."""
    content_hash: str
    text_preview: str
    reason: str
    marked_by: str
    marked_at: float
    actual_risk_score: int
    # If embedded into a future retraining set, recorded here.
    promoted_to_corpus: bool = False


@dataclass
class TenantPolicy:
    """In-memory state for one tenant."""
    tenant_id: str
    benigns: "OrderedDict[str, BenignRecord]" = field(default_factory=OrderedDict)
    attacks: list[MarkAttackRecord] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    # Track recent markings for rate-limit (sliding 60s window).
    _recent_markings: list[float] = field(default_factory=list)
    # Optional in-memory embeddings, parallel to benigns dict insertion order.
    # numpy arrays, None when SimilarityLayer is unavailable.
    _benign_embeddings: list[Any] = field(default_factory=list)


# ============================================================================
# Errors
# ============================================================================

class PoisoningRefused(Exception):
    """Raised when an attempt to mark content as benign is rejected because
    the content matches a critical-severity attack signal. The exception
    carries the offending threat IDs and the original risk_score so the
    caller (UI / API) can show an actionable error."""

    def __init__(self, threat_ids: list[str], risk_score: int):
        self.threat_ids = threat_ids
        self.risk_score = risk_score
        super().__init__(
            f"refused to whitelist content: it triggers critical threats "
            f"{threat_ids} (risk_score={risk_score}). Tenant feedback cannot "
            f"override critical Layer-1 findings — author a narrower pattern "
            f"suppression instead, or fix the upstream content."
        )


class RateLimited(Exception):
    """Raised when a tenant has exceeded the per-minute marking quota."""


class TenantStoreFull(Exception):
    """Raised when a tenant's benign store is at its cap and the new entry
    cannot evict an older one (e.g. the new entry is *itself* the oldest)."""


# ============================================================================
# TenantLearningStore
# ============================================================================

class TenantLearningStore:
    """Per-tenant continuous-learning state.

    Designed to be safe to hold on a singleton ``Analyzer`` shared across
    many tenants: every public method is thread-safe, and an internal lock
    protects each tenant's policy independently.

    Args:
        store_root: filesystem directory for persistence. Defaults to
            ``$MEMGAR_TENANT_STORE`` or ``~/.memgar/tenant_learning``.
        similarity_layer: a ready ``SimilarityLayer`` instance whose encoder
            we reuse for benign matching. When ``None``, the store still
            works with hash-only matching (no near-duplicate detection).
        ephemeral: when True, no on-disk persistence (useful for tests).
    """

    def __init__(
        self,
        store_root: Optional[Path] = None,
        similarity_layer: Any = None,
        ephemeral: bool = False,
    ) -> None:
        self._root = Path(store_root) if store_root is not None else _default_store_root()
        self._ephemeral = bool(ephemeral)
        self._similarity = similarity_layer  # may be None
        self._tenants: dict[str, TenantPolicy] = {}
        self._lock = threading.RLock()
        if not self._ephemeral:
            try:
                self._root.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                logger.warning("tenant_learning: cannot create store root %s (%s); falling back to ephemeral", self._root, exc)
                self._ephemeral = True

    # ------------------------------------------------------------------ utils

    def _tenant_dir(self, tenant_id: str) -> Path:
        # Defensive: tenant_id may come from untrusted metadata. Sanitize so
        # it cannot escape the store_root (no path traversal).
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", tenant_id)[:64] or "default"
        return self._root / safe

    def _get_or_load(self, tenant_id: str) -> TenantPolicy:
        with self._lock:
            pol = self._tenants.get(tenant_id)
            if pol is not None:
                return pol
            pol = self._load_from_disk(tenant_id)
            self._tenants[tenant_id] = pol
            return pol

    def _load_from_disk(self, tenant_id: str) -> TenantPolicy:
        pol = TenantPolicy(tenant_id=tenant_id)
        if self._ephemeral:
            return pol
        tdir = self._tenant_dir(tenant_id)
        if not tdir.exists():
            return pol
        meta_path = tdir / "policy.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                pol.created_at = float(meta.get("created_at", pol.created_at))
                pol.updated_at = float(meta.get("updated_at", pol.updated_at))
            except Exception as exc:
                logger.warning("tenant_learning: corrupt policy.json for %s (%s) — starting fresh", tenant_id, exc)
        benigns_path = tdir / "benigns.jsonl"
        if benigns_path.exists():
            try:
                for line in benigns_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    d = json.loads(line)
                    rec = BenignRecord(**d)
                    pol.benigns[rec.content_hash] = rec
            except Exception as exc:
                logger.warning("tenant_learning: corrupt benigns.jsonl for %s (%s)", tenant_id, exc)
        # Rebuild in-memory embeddings if similarity layer is available.
        if self._similarity is not None and pol.benigns:
            self._rebuild_embeddings(pol)
        attacks_path = tdir / "attacks.jsonl"
        if attacks_path.exists():
            try:
                for line in attacks_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    pol.attacks.append(MarkAttackRecord(**json.loads(line)))
            except Exception as exc:
                logger.warning("tenant_learning: corrupt attacks.jsonl for %s (%s)", tenant_id, exc)
        return pol

    def _rebuild_embeddings(self, pol: TenantPolicy) -> None:
        """Recompute the parallel embedding list for an existing tenant
        policy. Called at load time."""
        sl = self._similarity
        if sl is None or not getattr(sl, "available", False):
            return
        try:
            embs = []
            for rec in pol.benigns.values():
                embs.append(sl._cached_encode(rec.text_preview))
            pol._benign_embeddings = embs
        except Exception as exc:
            logger.warning("tenant_learning: embedding rebuild failed for %s (%s)", pol.tenant_id, exc)
            pol._benign_embeddings = []

    def _persist(self, pol: TenantPolicy) -> None:
        if self._ephemeral:
            return
        tdir = self._tenant_dir(pol.tenant_id)
        tdir.mkdir(parents=True, exist_ok=True)
        # Policy meta
        meta = {
            "tenant_id": pol.tenant_id,
            "created_at": pol.created_at,
            "updated_at": pol.updated_at,
            "n_benigns": len(pol.benigns),
            "n_attacks": len(pol.attacks),
        }
        (tdir / "policy.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        # Benigns
        lines = []
        for rec in pol.benigns.values():
            d = asdict(rec)
            lines.append(json.dumps(d, ensure_ascii=False))
        (tdir / "benigns.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        # Attacks
        lines = []
        for rec in pol.attacks:
            lines.append(json.dumps(asdict(rec), ensure_ascii=False))
        (tdir / "attacks.jsonl").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    def _audit(self, tenant_id: str, action: str, payload: dict) -> None:
        if self._ephemeral:
            return
        tdir = self._tenant_dir(tenant_id)
        tdir.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.time(), "action": action, **payload}
        with (tdir / "audit.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _enforce_rate_limit(self, pol: TenantPolicy) -> None:
        now = time.time()
        cutoff = now - 60.0
        pol._recent_markings = [t for t in pol._recent_markings if t >= cutoff]
        if len(pol._recent_markings) >= MAX_MARKINGS_PER_MINUTE:
            raise RateLimited(
                f"tenant {pol.tenant_id} exceeded {MAX_MARKINGS_PER_MINUTE} markings/min"
            )
        pol._recent_markings.append(now)

    # --------------------------------------------------------------- mark API

    def mark_as_benign(
        self,
        tenant_id: str,
        content: str,
        reason: str,
        marked_by: str = "system",
        *,
        analyzer_result: Any = None,
    ) -> BenignRecord:
        """Tell memgar that *this content* is benign for this tenant.

        Anti-poisoning: if the caller passes ``analyzer_result`` (the
        ``AnalysisResult`` from the original ``analyzer.analyze(entry)``
        call) and it contains a CRITICAL severity threat OR has
        ``risk_score >= CRITICAL_RISK_FLOOR``, the call is refused. This
        prevents an attacker with feedback access from whitelisting real
        memory-poisoning payloads.
        """
        if not content or not content.strip():
            raise ValueError("cannot mark empty content as benign")

        # Anti-poisoning gate
        if analyzer_result is not None:
            try:
                from memgar.models import Severity  # local import to avoid cycle
                threat_ids = []
                for t in getattr(analyzer_result, "threats", []) or []:
                    sev = getattr(getattr(t, "threat", None), "severity", None)
                    if sev == Severity.CRITICAL:
                        threat_ids.append(getattr(t.threat, "id", "?"))
                risk = int(getattr(analyzer_result, "risk_score", 0))
                if threat_ids or risk >= CRITICAL_RISK_FLOOR:
                    raise PoisoningRefused(threat_ids, risk)
            except PoisoningRefused:
                raise
            except Exception:
                # If we can't introspect, fail safe → don't accept.
                logger.exception("tenant_learning: anti-poisoning check errored; refusing")
                raise PoisoningRefused(["unknown"], 100)

        h = _content_hash(content)
        with self._lock:
            pol = self._get_or_load(tenant_id)
            self._enforce_rate_limit(pol)

            now = time.time()
            existing = pol.benigns.get(h)
            if existing is not None:
                existing.use_count = int(existing.use_count)  # idempotent
                existing.last_used_at = now
                pol.updated_at = now
                self._persist(pol)
                self._audit(tenant_id, "mark_benign:dup", {"hash": h, "marked_by": marked_by})
                return existing

            # Cap with LRU eviction
            if len(pol.benigns) >= MAX_BENIGNS_PER_TENANT:
                # Evict the least-recently-used (oldest last_used_at)
                evict_key = min(pol.benigns, key=lambda k: pol.benigns[k].last_used_at or pol.benigns[k].marked_at)
                if evict_key == h:
                    raise TenantStoreFull(f"tenant {tenant_id} benign store at cap and new entry would evict itself")
                evict_idx = list(pol.benigns).index(evict_key)
                del pol.benigns[evict_key]
                if 0 <= evict_idx < len(pol._benign_embeddings):
                    pol._benign_embeddings.pop(evict_idx)

            rec = BenignRecord(
                content_hash=h,
                text_preview=content[:120],
                reason=reason or "",
                marked_by=marked_by,
                marked_at=now,
                last_used_at=now,
            )
            pol.benigns[h] = rec

            # Compute embedding for similarity matching (if available).
            if self._similarity is not None and getattr(self._similarity, "available", False):
                try:
                    emb = self._similarity._cached_encode(content)
                    pol._benign_embeddings.append(emb)
                except Exception as exc:
                    logger.warning("tenant_learning: embed failed (%s) — falling back to hash-only for this entry", exc)
                    pol._benign_embeddings.append(None)
            else:
                pol._benign_embeddings.append(None)

            pol.updated_at = now
            self._persist(pol)
            self._audit(tenant_id, "mark_benign", {"hash": h, "marked_by": marked_by, "reason": reason[:80]})
            return rec

    def mark_as_attack(
        self,
        tenant_id: str,
        content: str,
        reason: str,
        marked_by: str = "system",
        analyzer_result: Any = None,
    ) -> MarkAttackRecord:
        """Flag a content as a missed attack. This does NOT change memgar's
        decision on future requests — it queues the sample for inclusion in
        an audit / retraining corpus. Authorised reviewers (you, not the
        tenant) decide whether to promote it to the canonical dataset."""
        if not content or not content.strip():
            raise ValueError("cannot mark empty content")
        h = _content_hash(content)
        risk = int(getattr(analyzer_result, "risk_score", 0)) if analyzer_result is not None else 0
        with self._lock:
            pol = self._get_or_load(tenant_id)
            self._enforce_rate_limit(pol)
            rec = MarkAttackRecord(
                content_hash=h,
                text_preview=content[:120],
                reason=reason or "",
                marked_by=marked_by,
                marked_at=time.time(),
                actual_risk_score=risk,
            )
            pol.attacks.append(rec)
            pol.updated_at = time.time()
            self._persist(pol)
            self._audit(tenant_id, "mark_attack", {"hash": h, "marked_by": marked_by, "reason": reason[:80]})
            return rec

    # ------------------------------------------------------------- match API

    def lookup_benign(self, tenant_id: str, content: str) -> tuple[Optional[BenignRecord], float]:
        """Return ``(record, similarity)`` if ``content`` matches an existing
        benign entry for this tenant. ``similarity`` is 1.0 for an exact
        hash hit, or the cosine similarity for an embedding match. When no
        match, returns ``(None, 0.0)``."""
        if not content:
            return None, 0.0
        h = _content_hash(content)
        with self._lock:
            pol = self._tenants.get(tenant_id) or self._load_from_disk(tenant_id)
            self._tenants[tenant_id] = pol
            # 1) exact hash
            rec = pol.benigns.get(h)
            if rec is not None:
                rec.use_count += 1
                rec.last_used_at = time.time()
                return rec, 1.0
            # 2) embedding similarity (top match)
            if not pol._benign_embeddings or self._similarity is None or not getattr(self._similarity, "available", False):
                return None, 0.0
            try:
                import numpy as np
                vec = self._similarity._cached_encode(content)
                best_sim = 0.0
                best_idx = -1
                for i, e in enumerate(pol._benign_embeddings):
                    if e is None:
                        continue
                    sim = float(np.dot(e, vec))
                    if sim > best_sim:
                        best_sim = sim
                        best_idx = i
                if best_idx >= 0 and best_sim >= SIM_DAMPEN_FLOOR:
                    rec = list(pol.benigns.values())[best_idx]
                    rec.use_count += 1
                    rec.last_used_at = time.time()
                    return rec, best_sim
            except Exception:
                logger.exception("tenant_learning: similarity lookup failed")
            return None, 0.0

    # --------------------------------------------------------------- admin API

    def forget_tenant(self, tenant_id: str) -> int:
        """Forget everything memgar learned for a tenant. Returns the number
        of benign entries removed. Used for GDPR / right-to-erasure flows."""
        with self._lock:
            pol = self._tenants.pop(tenant_id, None)
            n = len(pol.benigns) if pol else 0
            if not self._ephemeral:
                import shutil
                tdir = self._tenant_dir(tenant_id)
                if tdir.exists():
                    shutil.rmtree(tdir, ignore_errors=True)
            return n

    def stats(self, tenant_id: str) -> dict:
        with self._lock:
            pol = self._tenants.get(tenant_id) or self._load_from_disk(tenant_id)
            self._tenants[tenant_id] = pol
            return {
                "tenant_id": tenant_id,
                "n_benigns": len(pol.benigns),
                "n_attacks": len(pol.attacks),
                "n_embeddings": sum(1 for e in pol._benign_embeddings if e is not None),
                "created_at": pol.created_at,
                "updated_at": pol.updated_at,
            }


# ============================================================================
# Risk-score adjustment helper (used by Analyzer)
# ============================================================================

def compute_dampen(risk_score: int, similarity: float, threat_severities: list) -> int:
    """Compute how much to lower risk_score given a benign match.

    Returns 0 (no dampen) when:
    * risk_score >= CRITICAL_RISK_FLOOR — even with full benign match, a
      high-risk score is not overridden
    * any threat is CRITICAL severity — same reason
    * similarity < SIM_DAMPEN_FLOOR — too weak to act on
    """
    from memgar.models import Severity
    if risk_score >= CRITICAL_RISK_FLOOR:
        return 0
    if any(s == Severity.CRITICAL for s in threat_severities):
        return 0
    if similarity < SIM_DAMPEN_FLOOR:
        return 0
    # Scale: at floor → 0, at 1.0 → MAX_DAMPEN. Linear.
    scaled = (similarity - SIM_DAMPEN_FLOOR) / (1.0 - SIM_DAMPEN_FLOOR)
    return int(MAX_DAMPEN * max(0.0, min(1.0, scaled)))
