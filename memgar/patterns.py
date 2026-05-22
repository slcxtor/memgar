"""Threat pattern database — loaded from memgar/data/patterns.yaml.

Public API is identical to the old code-as-data version:

    from memgar.patterns import PATTERNS, get_pattern_by_id, get_patterns_cached
"""

from __future__ import annotations

import hashlib
import os
import pickle  # nosec B403
from pathlib import Path
from typing import Optional

import yaml

from memgar.models import Severity, Threat, ThreatCategory

_DATA_FILE = Path(__file__).parent / "data" / "patterns.yaml"
_CACHE_KEY = "patterns_v2.pkl"


# ---------------------------------------------------------------------------
# Cache helpers (same security model as v1: restricted unpickler)
# ---------------------------------------------------------------------------

def _get_cache_path() -> Path:
    cache_dir = os.environ.get("MEMGAR_CACHE_DIR", "").strip()
    base = Path(cache_dir) if cache_dir else Path(os.path.expanduser("~")) / ".cache" / "memgar"
    base.mkdir(parents=True, exist_ok=True)
    return base / _CACHE_KEY


def _data_hash() -> str:
    return hashlib.sha256(_DATA_FILE.read_bytes()).hexdigest()[:16]


class _SafeUnpickler(pickle.Unpickler):
    _ALLOWED = {
        ("builtins", "dict"), ("builtins", "list"), ("builtins", "tuple"),
        ("builtins", "str"), ("builtins", "int"), ("builtins", "float"),
        ("builtins", "bool"), ("builtins", "NoneType"),
        ("memgar.models", "Threat"), ("memgar.models", "ThreatCategory"),
        ("memgar.models", "Severity"),
    }

    def find_class(self, module: str, name: str):
        if (module, name) not in self._ALLOWED:
            raise pickle.UnpicklingError(f"Forbidden: {module}.{name}")
        return super().find_class(module, name)


def _load_cache() -> Optional[list[Threat]]:
    try:
        p = _get_cache_path()
        if not p.exists():
            return None
        with p.open("rb") as f:
            payload = _SafeUnpickler(f).load()
        if payload.get("hash") != _data_hash():
            return None
        return payload["patterns"]
    except Exception:
        return None


def _save_cache(patterns: list[Threat]) -> None:
    try:
        p = _get_cache_path()
        with p.open("wb") as f:
            pickle.dump({"hash": _data_hash(), "patterns": patterns}, f, protocol=5)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

_SEV = {s.value: s for s in Severity}
_CAT = {c.value: c for c in ThreatCategory}


def _load_yaml() -> list[Threat]:
    raw = yaml.safe_load(_DATA_FILE.read_text(encoding="utf-8"))
    out: list[Threat] = []
    for rec in raw:
        out.append(Threat(
            id=rec["id"],
            name=rec["name"],
            description=rec.get("description", ""),
            category=_CAT.get(rec.get("category", ""), ThreatCategory.ANOMALY),
            severity=_SEV.get(rec.get("severity", ""), Severity.MEDIUM),
            patterns=rec.get("patterns") or [],
            keywords=rec.get("keywords") or [],
            examples=rec.get("examples") or [],
            mitre_attack=rec.get("mitre_attack"),
        ))
    return out


def _build_patterns() -> list[Threat]:
    cached = _load_cache()
    if cached is not None:
        return cached
    patterns = _load_yaml()
    _save_cache(patterns)
    return patterns


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

PATTERNS: list[Threat] = _build_patterns()


def get_patterns_cached() -> list[Threat]:
    """Return PATTERNS (already loaded from cache on import)."""
    return PATTERNS


def get_pattern_by_id(threat_id: str) -> Optional[Threat]:
    for p in PATTERNS:
        if p.id == threat_id:
            return p
    return None


def get_patterns_by_severity(severity: Severity) -> list[Threat]:
    return [p for p in PATTERNS if p.severity == severity]


def get_patterns_by_category(category: ThreatCategory) -> list[Threat]:
    return [p for p in PATTERNS if p.category == category]


def get_critical_patterns() -> list[Threat]:
    return get_patterns_by_severity(Severity.CRITICAL)


def get_high_patterns() -> list[Threat]:
    return get_patterns_by_severity(Severity.HIGH)


def get_all_keywords() -> set[str]:
    keywords: set[str] = set()
    for p in PATTERNS:
        keywords.update(p.keywords)
    return keywords


def pattern_stats() -> dict[str, int]:
    return {
        "total": len(PATTERNS),
        "critical": len(get_patterns_by_severity(Severity.CRITICAL)),
        "high": len(get_patterns_by_severity(Severity.HIGH)),
        "medium": len(get_patterns_by_severity(Severity.MEDIUM)),
        "low": len(get_patterns_by_severity(Severity.LOW)),
        "info": len(get_patterns_by_severity(Severity.INFO)),
    }
