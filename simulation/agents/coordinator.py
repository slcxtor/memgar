"""Coordinator: trusted orchestrator.

The coordinator owns the agent registry, sets up trust relationships
in shielded mode, and is the only agent allowed to ask the finance
agent to actually execute a payment.

It is also where cross-agent messages must pass when the shielded
runtime is active: AgentSecurityGuard validates every message it
relays.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from memgar.agents import AgentSecurityGuard, TrustLevel

from ..world import Message
from .base import BaseAgent


class CoordinatorAgent(BaseAgent):
    role = "coordinator"

    def __init__(self, *args, shielded: bool = False, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.shielded = shielded
        self.security: Optional[AgentSecurityGuard] = (
            AgentSecurityGuard(strict_mode=False) if shielded else None
        )
        self._known_agents: List[str] = []
        self.blocked_messages: List[Dict[str, Any]] = []

    def register(self, agent_name: str, *, role: str) -> None:
        self._known_agents.append(agent_name)
        if self.security is not None:
            # Self → known internal agents = HIGH trust
            self.security.set_trust(self.name, agent_name, TrustLevel.HIGH)
            self.security.set_trust(agent_name, self.name, TrustLevel.HIGH)

    def relay(self, source: str, target: str, body: str, kind: str = "request") -> bool:
        """Relay a message from one agent to another with validation."""
        if self.security is not None:
            assess = self.security.validate_message(source=source, target=target, message=body)
            if not assess.is_safe and assess.action.value == "block":
                self.blocked_messages.append({
                    "tick": self.world.tick,
                    "source": source, "target": target, "risk": assess.overall_risk,
                    "preview": body[:120],
                })
                self.record("relay_blocked", source=source, target=target, risk=assess.overall_risk)
                return False
        self.world.post(Message(
            msg_id=self.world.new_id("relay"),
            sender=source, recipient=target,
            channel="agent_bus", kind=kind, body=body,
            tick=self.world.tick,
        ))
        self.record("relay_ok", source=source, target=target)
        return True

    def step(self) -> None:
        # Drain own inbox – mostly alerts and status reports
        for msg in self.world.drain(self.name):
            self.record("absorb_status", sender=msg.sender,
                        message_kind=msg.kind, preview=msg.body[:120])
