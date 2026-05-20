"""E-mail triage agent.

Sits at the front door of the agent network. It receives raw inbound
mail and decides which downstream agent to forward to. A naive triage
agent will forward anything that looks vaguely on-topic; with the
shield, the message is run through the analyzer first and obvious
poisoning attempts are dropped on the floor with a short report to
the coordinator.
"""

from __future__ import annotations

from typing import List, Optional

from memgar import Analyzer, MemoryEntry, Decision
from memgar.agents import SwarmDetector

from ..world import Message
from .base import BaseAgent


class TriageAgent(BaseAgent):
    role = "email_triage"

    def __init__(self, *args, shielded: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.shielded = shielded
        self._analyzer = Analyzer(use_llm=False) if shielded else None
        self._swarm = SwarmDetector() if shielded else None
        self.swarm_alerts: List[dict] = []

    def _route(self, msg: Message) -> Optional[str]:
        body = (msg.body or "").lower()
        if any(k in body for k in ("payment", "invoice", "wire", "iban", "bank", "pay", "transfer")):
            return "finance"
        if any(k in body for k in ("research", "policy", "spec", "doc", "report", "rfc")):
            return "researcher"
        return "support"

    def step(self) -> None:
        pending = [m for m in self.world.drain(self.name) if m.channel == "email"]
        # ---- shielded: bulk-report to swarm detector first so a flood of
        # near-identical poison emails is caught before any forward happens.
        swarm_blocked: set[str] = set()
        if self.shielded and self._swarm is not None and pending:
            for msg in pending:
                self._swarm.report_activity(
                    agent_id=msg.sender, action="email",
                    target=self._route(msg) or "support",
                    content=msg.body[:200],
                )
            threats = self._swarm.detect_swarm_threats()
            for t in threats:
                self.swarm_alerts.append({
                    "tick": self.world.tick,
                    "type": str(getattr(t, "threat_type", "?")),
                    "agents": list(getattr(t, "agents_involved", []) or []),
                })
                for ag in getattr(t, "agents_involved", []) or []:
                    swarm_blocked.add(ag)

        for msg in pending:
            target = self._route(msg) or "support"
            if msg.sender in swarm_blocked:
                self.record("swarm_drop", sender=msg.sender, target=target)
                self.world.post(Message(
                    msg_id=self.world.new_id("triage"),
                    sender=self.name, recipient="coordinator",
                    channel="agent_bus", kind="alert",
                    body=f"Swarm-blocked email from {msg.sender}",
                    tick=self.world.tick,
                ))
                continue

            if self.shielded and self._analyzer is not None:
                entry = MemoryEntry(
                    content=msg.body,
                    source_type="email",
                    source_id=msg.sender,
                )
                res = self._analyzer.analyze(entry)
                if res.decision == Decision.BLOCK:
                    self.record("drop_email", sender=msg.sender, risk=res.risk_score, decision="block")
                    # Notify coordinator instead of forwarding
                    self.world.post(Message(
                        msg_id=self.world.new_id("triage"),
                        sender=self.name, recipient="coordinator",
                        channel="agent_bus", kind="alert",
                        body=f"Blocked email from {msg.sender}: risk={res.risk_score}",
                        tick=self.world.tick,
                    ))
                    continue

            # forward (preserve metadata)
            self.world.post(Message(
                msg_id=self.world.new_id("fwd"),
                sender=self.name,
                recipient=target,
                channel="email",
                kind=msg.kind,
                body=msg.body,
                tick=self.world.tick,
                metadata={**(msg.metadata or {}), "original_sender": msg.sender},
            ))
            self.record("forward_email", sender=msg.sender, target=target)
