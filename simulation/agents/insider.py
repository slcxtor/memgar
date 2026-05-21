"""Insider adversary — a compromised internal agent.

This is the *second* adversary in the simulation. Unlike the external
attacker who must inject through email / RAG / MCP boundaries, the
insider has valid credentials. They sit at the same trust tier as
'researcher' (HIGH inter-agent trust with the coordinator) and can
post directly on the agent bus.

This is the hardest defender problem: every individual action the
insider takes looks plausible — a research note, a policy summary, a
tool call within their normal scope. Their attack succeeds via
*combinations* and *timing*. Memgar's behavioural baseline and
trust-chain layers are designed precisely for this.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..world import Message
from .base import BaseAgent


class InsiderAgent(BaseAgent):
    role = "insider_researcher"

    def __init__(self, *args, target_finance: str = "finance",
                 target_support: str = "support", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.target_finance = target_finance
        self.target_support = target_support
        self._playbook: List[Dict[str, Any]] = []

    def queue(self, action: str, **fields: Any) -> None:
        """Scenario code calls this to schedule one insider action.

        Each item is a dict with at least an `action` and optional
        `target`, `body`, `tools`, `delay_ticks`.
        """
        self._playbook.append({"action": action, **fields})

    def step(self) -> None:
        # Drain own inbox — pretend to be a real agent.
        for _ in self.world.drain(self.name):
            pass

        # Execute any queued actions whose delay has elapsed.
        remaining: List[Dict[str, Any]] = []
        for item in self._playbook:
            wait = int(item.get("delay_ticks", 0) or 0)
            if wait > 0:
                item["delay_ticks"] = wait - 1
                remaining.append(item)
                continue
            self._dispatch(item)
        self._playbook = remaining

    def _dispatch(self, item: Dict[str, Any]) -> None:
        action = item["action"]
        if action == "post_research_note":
            self.world.post(Message(
                msg_id=self.world.new_id("insider"),
                sender=self.name,
                recipient=item.get("target", self.target_support),
                channel="agent_bus",
                kind="memory_write",
                body=item["body"],
                tick=self.world.tick,
                metadata={"insider_origin": True},
            ))
            self.record("post_research_note", target=item.get("target"))
        elif action == "tool_call":
            tools = item.get("tools")
            if tools is None:
                return
            res = tools.invoke(item["tool"], item.get("params", {}))
            self.record("tool_call", tool=item["tool"],
                        allowed=res.allowed, rationale=res.rationale)
