"""Virtual world: clock, message bus, audit log, deterministic RNG.

The world is the only thing every agent and every attacker share. It is
deliberately tiny but realistic enough that:

  * Time advances in discrete "ticks" (one minute per tick).
  * Inter-agent messages are routed through a bus, not function calls,
    so an outside attacker can drop in messages the same way a real one
    would through SMTP / webhook / MCP.
  * Every interaction is logged with provenance to a JSONL audit file
    so the post-mortem reporter can reconstruct exactly what happened.
"""

from __future__ import annotations

import json
import random
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Message:
    """An envelope on the inter-agent bus.

    `sender` is the *claimed* source — an attacker can lie about it,
    which is precisely the kind of thing memgar trust-chain must catch.
    """

    msg_id: str
    sender: str
    recipient: str
    channel: str        # "agent_bus" | "email" | "rag_ingest" | "tool_result"
    kind: str           # "request" | "instruction" | "memory_write" | "document"
    body: str
    tick: int
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEntry:
    tick: int
    actor: str
    event: str
    payload: Dict[str, Any]


class World:
    """The shared state of the simulation."""

    def __init__(self, *, seed: int = 1337, scenario: str = "default") -> None:
        self.tick: int = 0
        self.rng = random.Random(seed)
        self.scenario = scenario
        self._bus: Dict[str, List[Message]] = {}
        self._audit: List[AuditEntry] = []
        self._subscribers: Dict[str, List[Callable[[Message], None]]] = {}
        self._started = time.time()

    # -- messaging -------------------------------------------------------

    def post(self, msg: Message) -> None:
        self._bus.setdefault(msg.recipient, []).append(msg)
        self.audit(msg.sender, "post", {
            "to": msg.recipient,
            "channel": msg.channel,
            "kind": msg.kind,
            "preview": msg.body[:120],
        })
        for cb in self._subscribers.get(msg.recipient, []):
            cb(msg)

    def inbox(self, recipient: str) -> List[Message]:
        return list(self._bus.get(recipient, []))

    def drain(self, recipient: str) -> List[Message]:
        items = self._bus.get(recipient, [])
        self._bus[recipient] = []
        return items

    def subscribe(self, recipient: str, cb: Callable[[Message], None]) -> None:
        self._subscribers.setdefault(recipient, []).append(cb)

    # -- time ------------------------------------------------------------

    def advance(self) -> None:
        self.tick += 1

    # -- audit -----------------------------------------------------------

    def audit(self, actor: str, event: str, payload: Optional[Dict[str, Any]] = None) -> None:
        self._audit.append(AuditEntry(
            tick=self.tick, actor=actor, event=event, payload=payload or {},
        ))

    def dump_audit(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for entry in self._audit:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def new_id(prefix: str = "msg") -> str:
        return f"{prefix}-{uuid.uuid4().hex[:10]}"
