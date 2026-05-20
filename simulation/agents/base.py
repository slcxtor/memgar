"""Base class for every simulated agent.

An agent owns:

* a stable `name`
* a memory store (raw or shielded — same interface)
* a per-tick `step()` that pulls messages and acts

It does NOT own its own tools or RAG. Those are passed in from the
world so the same agent can run shielded or unshielded by swapping
infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from ..world import Message, World


class MemoryStoreProtocol(Protocol):
    def write(self, content: str, *, source_type: str, source_id: Optional[str],
              tick: int, **kwargs: Any) -> Any: ...
    def recall(self, query: str, top_k: int = 5) -> List[Any]: ...
    def all(self) -> List[Any]: ...


@dataclass
class AgentReport:
    name: str
    actions: List[Dict[str, Any]]
    accepted_writes: int
    rejected_writes: int
    suspicious_followups: int = 0


class BaseAgent:
    def __init__(self, name: str, memory: MemoryStoreProtocol, world: World) -> None:
        self.name = name
        self.memory = memory
        self.world = world
        self.actions: List[Dict[str, Any]] = []

    # -- bookkeeping helpers -------------------------------------------

    def record(self, kind: str, **fields: Any) -> None:
        self.actions.append({"tick": self.world.tick, "kind": kind, **fields})

    def _absorb(self, msg: Message, *, source_type: str, source_domain: Optional[str] = None,
                verified: bool = False, tags: Optional[List[str]] = None) -> Any:
        """Store an incoming message in memory, going through whatever
        memory store this agent was wired with."""
        return self.memory.write(
            msg.body,
            source_type=source_type,
            source_id=msg.sender,
            source_name=msg.sender,
            source_domain=source_domain,
            verified=verified,
            tick=self.world.tick,
            tags=tags or [],
        )

    # -- subclasses override --------------------------------------------

    def step(self) -> None:
        raise NotImplementedError

    def report(self) -> AgentReport:
        accepted = 0
        rejected = 0
        for rec in self.memory.all():
            if getattr(rec, "accepted", True):
                accepted += 1
            else:
                rejected += 1
        # Count rejections that never made it to .all() but live in events
        events = getattr(self.memory, "events", None)
        if events is not None:
            rejected = sum(1 for e in events if not e.get("allowed", True))
            accepted = sum(1 for e in events if e.get("allowed", True))
        return AgentReport(
            name=self.name,
            actions=self.actions,
            accepted_writes=accepted,
            rejected_writes=rejected,
        )
