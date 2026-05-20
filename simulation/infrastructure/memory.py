"""Per-agent persistent memory.

Two layers:

* `RawMemoryStore` - what a naive agent uses: dict + list, no provenance,
  no integrity, no analysis. This is the baseline against which the
  shielded variant is compared.
* `ShieldedMemoryStore` - wraps `MemgarDefensePipeline` so every write
  passes through sanitisation, write-ahead validation, the tamper-evident
  ledger, behavioural baselining, and the trust-aware retriever.

Both expose the same `write` / `recall` / `dump` surface so the agent
implementation does not change between the unshielded and shielded runs.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from memgar.defense_pipeline import MemgarDefensePipeline, DefensePipelineResult
from memgar.memory_ledger import MemoryLedger


@dataclass
class MemoryRecord:
    entry_id: str
    content: str
    source_type: str
    source_id: str
    tick: int
    accepted: bool = True
    decision: str = "allow"
    risk_score: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


class RawMemoryStore:
    """Naive memory: append-anything, recall-anything."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        self._records: List[MemoryRecord] = []

    def write(
        self,
        content: str,
        *,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        tick: int = 0,
        **_: Any,
    ) -> MemoryRecord:
        rec = MemoryRecord(
            entry_id=f"raw-{len(self._records):04d}",
            content=content,
            source_type=source_type,
            source_id=source_id or "unknown",
            tick=tick,
        )
        self._records.append(rec)
        return rec

    def recall(self, query: str, top_k: int = 5) -> List[MemoryRecord]:
        q = query.lower()
        scored: List[Tuple[float, MemoryRecord]] = []
        for r in self._records:
            base = sum(1 for tok in q.split() if tok and tok in r.content.lower())
            # Recency tiebreak: newer entries rank higher, like a real
            # "latest known fact" memory.
            score = base + (r.tick * 1e-3)
            if base:
                scored.append((score, r))
        scored.sort(key=lambda x: -x[0])
        if not scored:
            return self._records[-top_k:]
        return [r for _, r in scored[:top_k]]

    def all(self) -> List[MemoryRecord]:
        return list(self._records)


class ShieldedMemoryStore:
    """Memory protected by the full MemgarDefensePipeline."""

    def __init__(
        self,
        agent_id: str,
        *,
        ledger_path: Optional[Path] = None,
        allow_quarantined_writes: bool = False,
    ) -> None:
        self.agent_id = agent_id
        self._records: List[MemoryRecord] = []
        ledger_path_str = str(ledger_path) if ledger_path else None
        self.pipeline = MemgarDefensePipeline(
            agent_id=agent_id,
            ledger_path=ledger_path_str,
            allow_quarantined_writes=allow_quarantined_writes,
            enable_behavioral_monitoring=True,
            enable_circuit_breaker=True,
        )
        self.events: List[Dict[str, Any]] = []

    def write(
        self,
        content: str,
        *,
        source_type: str = "unknown",
        source_id: Optional[str] = None,
        source_name: Optional[str] = None,
        source_url: Optional[str] = None,
        source_domain: Optional[str] = None,
        verified: bool = False,
        tick: int = 0,
        tags: Optional[List[str]] = None,
    ) -> MemoryRecord:
        result: DefensePipelineResult = self.pipeline.process_external_content(
            content=content,
            source_type=source_type,
            source_id=source_id,
            source_name=source_name,
            source_url=source_url,
            source_domain=source_domain,
            verified=verified,
            tags=tags or [],
        )

        decision = result.decision
        risk = 0
        if result.guard_result is not None:
            risk = int(getattr(result.guard_result, "risk_score", 0) or 0)

        rec = MemoryRecord(
            entry_id=f"shd-{len(self._records):04d}",
            content=(result.safe_content or content) if result.allowed else content,
            source_type=source_type,
            source_id=source_id or "unknown",
            tick=tick,
            accepted=result.allowed,
            decision=decision,
            risk_score=risk,
            extra={
                "warnings": list(result.warnings or []),
                "circuit_tripped": bool(result.circuit_tripped),
            },
        )
        self.events.append({
            "tick": tick,
            "decision": decision,
            "allowed": result.allowed,
            "risk": risk,
            "warnings": list(result.warnings or []),
            "preview": content[:140],
        })
        if result.allowed:
            self._records.append(rec)
        return rec

    def recall(self, query: str, top_k: int = 5) -> List[MemoryRecord]:
        q = query.lower()
        scored: List[Tuple[float, MemoryRecord]] = []
        for r in self._records:
            base = sum(1 for tok in q.split() if tok and tok in r.content.lower())
            score = base + (r.tick * 1e-3)
            if base:
                scored.append((score, r))
        scored.sort(key=lambda x: -x[0])
        if not scored:
            return self._records[-top_k:]
        return [r for _, r in scored[:top_k]]

    def all(self) -> List[MemoryRecord]:
        return list(self._records)

    def verify_integrity(self) -> Dict[str, Any]:
        try:
            report = self.pipeline.verify_memory()
            return {
                "valid": getattr(report, "is_valid", True),
                "tampered": getattr(report, "tampered_count", 0),
                "first_breach": getattr(report, "first_breach_index", None),
            }
        except Exception as exc:
            return {"valid": False, "error": str(exc)}
