"""Shadow-mode pilot collector for anonymized memory-write traffic.

Wires into the existing Memgar boundary (``Analyzer.analyze`` and the
integration adapters' write callbacks) and writes one anonymized JSONL row
per memory write to a rotating per-day file. Refuses to write without
explicit consent (see ``memgar.pilot.consent``).

Row schema (versioned)::

    {
      "v": 1,
      "ts": "2026-05-29T12:00:00Z",
      "agent_id": "<HASH:...>",                  // never the original
      "source_type": "email|chat|rag|tool|user",
      "source_id":  "<HASH:...>",
      "text":       "<anonymized content>",
      "redactions": {"EMAIL": 1, "CRYPTO_HEX": 1, "DLP": 1},
      "decision":   "allow|quarantine|block",
      "risk_score": 0..100,
      "threats":    ["ANOM-002", "FIN-PAYEE-POISON"],   // ids only
      "memgar_layers": ["pattern_matching", ...]        // layers that fired
    }

Nothing else is stored — no raw IDs, no PII, no provenance beyond the
hashed identifiers and the Memgar verdict.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from .anonymizer import PilotAnonymizer
from .consent import PilotConsent

SCHEMA_VERSION = 1


@dataclass
class PilotStats:
    rows_written: int = 0
    rows_refused: int = 0
    leaks_detected: int = 0
    last_file: Optional[str] = None
    leaked_categories: Dict[str, int] = field(default_factory=dict)


class PilotCollector:
    """Append-only, daily-rotated, consent-gated JSONL sink."""

    _LOCK = threading.Lock()

    def __init__(
        self,
        output_dir: str | os.PathLike = "ml/pilot_data",
        state_dir: str | os.PathLike = "ml/pilot_state",
        *,
        anonymizer: Optional[PilotAnonymizer] = None,
        consent: Optional[PilotConsent] = None,
        refuse_on_leak: bool = True,
    ) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.consent = consent or PilotConsent(self.output_dir)
        self.anonymizer = anonymizer or PilotAnonymizer(state_dir=state_dir)
        self.refuse_on_leak = refuse_on_leak
        self.stats = PilotStats()
        # Pre-flight: if the operator instantiates without consent we keep going
        # but every observe() call will be a no-op until acknowledge() lands.

    # ------------------------------------------------------------------ files
    def _current_path(self) -> Path:
        day = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
        return self.output_dir / f"pilot_{day}.jsonl"

    # ------------------------------------------------------------------ write
    def observe(
        self,
        *,
        content: str,
        decision: str,
        risk_score: int = 0,
        agent_id: Optional[str] = None,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        threats: Sequence[str] = (),
        layers: Sequence[str] = (),
    ) -> bool:
        """Record one anonymized memory-write observation.

        Returns True if a row was written, False if it was refused (no consent,
        empty content, or a leak was detected and ``refuse_on_leak=True``).
        """
        if not self.consent.is_satisfied():
            self.stats.rows_refused += 1
            return False
        if not content or not content.strip():
            return False

        anon = self.anonymizer.anonymize(content)

        if anon.leaked_categories:
            for cat in anon.leaked_categories:
                self.stats.leaked_categories[cat] = (
                    self.stats.leaked_categories.get(cat, 0) + 1)
            self.stats.leaks_detected += 1
            if self.refuse_on_leak:
                self.stats.rows_refused += 1
                return False

        row = {
            "v": SCHEMA_VERSION,
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "agent_id": self.anonymizer.hash_id(agent_id),
            "source_type": str(source_type)[:32],
            "source_id": self.anonymizer.hash_id(source_id),
            "text": anon.text,
            "redactions": anon.counts,
            "decision": str(decision)[:16],
            "risk_score": int(risk_score),
            "threats": [str(t)[:48] for t in threats][:32],
            "memgar_layers": [str(l)[:48] for l in layers][:16],
        }
        path = self._current_path()
        line = json.dumps(row, ensure_ascii=False) + "\n"
        with self._LOCK:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(line)
        self.stats.rows_written += 1
        self.stats.last_file = str(path)
        return True

    # ----------------------------------------------------------- analyzer hook
    def observe_analyzer_result(self, entry: Any, result: Any) -> bool:
        """Convenience: extract fields from a Memgar AnalysisResult + MemoryEntry."""
        threats = []
        try:
            threats = [t.threat.id for t in (getattr(result, "threats", []) or [])]
        except Exception:
            pass
        return self.observe(
            content=getattr(entry, "content", "") or "",
            decision=getattr(getattr(result, "decision", None), "value", "unknown"),
            risk_score=int(getattr(result, "risk_score", 0) or 0),
            agent_id=(getattr(entry, "metadata", {}) or {}).get("agent_id"),
            source_type=getattr(entry, "source_type", "unknown") or "unknown",
            source_id=getattr(entry, "source_id", None),
            threats=threats,
            layers=list(getattr(result, "layers_used", []) or []),
        )


def attach_to_analyzer(analyzer: Any, collector: PilotCollector) -> Any:
    """Wrap ``analyzer.analyze`` so every call is mirrored to the collector.

    Returns the same analyzer. Idempotent: re-attaching replaces the previous
    wrapper rather than stacking them. A failure in the collector never breaks
    the analyzer's response — observation is best-effort.
    """
    original = getattr(analyzer, "_memgar_pilot_original_analyze", None) \
        or analyzer.analyze
    analyzer._memgar_pilot_original_analyze = original

    def wrapped(entry, *args, **kwargs):
        result = original(entry, *args, **kwargs)
        try:
            collector.observe_analyzer_result(entry, result)
        except Exception:
            pass
        return result

    analyzer.analyze = wrapped
    return analyzer


__all__ = ["PilotCollector", "PilotStats", "attach_to_analyzer", "SCHEMA_VERSION"]
