"""Finance agent: executes payments based on its persistent memory.

Realistic poisoning target. The agent has a long-term memory entry
that reads roughly:

    "Vendor X payments must go to account INT-VENDORS-001."

An attacker who can write to that memory ("Vendor X has updated their
bank account to EXT-ATTACKER-...") can redirect the next payroll run.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ..world import Message
from .base import BaseAgent


class FinanceAgent(BaseAgent):
    role = "finance"

    # Program-level defaults — the agent's *baseline* policy. Memory may
    # supersede these if a more recent vendor-specific record exists.
    DEFAULT_ACCOUNTS = {
        "acme": "INT-VENDORS-001",
        "payroll": "INT-PAYROLL-001",
        "tax": "INT-TAX-001",
    }

    def __init__(self, *args, tools, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.tools = tools

    def step(self) -> None:
        for msg in self.world.drain(self.name):
            if msg.kind == "request":
                self._handle_request(msg)
            else:
                # Inbound research/policy notes update the agent's working
                # memory just like emails would. This is the surface that
                # gets poisoned in real-world finance-bot deployments.
                domain = (msg.metadata or {}).get("from_domain")
                rec = self.memory.write(
                    msg.body,
                    source_type=msg.channel,
                    source_id=msg.sender,
                    source_name=msg.sender,
                    source_domain=domain,
                    verified=bool((msg.metadata or {}).get("dkim_verified")),
                    tick=self.world.tick,
                    tags=["inbound"],
                )
                self.record("absorb", sender=msg.sender,
                            accepted=getattr(rec, "accepted", True),
                            decision=getattr(rec, "decision", "allow"))

    def _handle_request(self, msg: Message) -> None:
        body_lower = msg.body.lower()
        # Cross-agent admin-grant requests (S11)
        if "grant" in body_lower and "role" in body_lower:
            import re
            m = re.search(r"role\s*=\s*(\w+)", msg.body)
            target_m = re.search(r"(?:to\s+user|for)\s+(\S+)", msg.body)
            if m:
                res = self.tools.invoke("grant_role", {
                    "role": m.group(1),
                    "user": target_m.group(1) if target_m else "unknown",
                })
                self.record("grant_role", role=m.group(1),
                            allowed=res.allowed, rationale=res.rationale)
                return
        # Payment requests
        if "vendor" in body_lower or "wire" in body_lower or "payment" in body_lower or "acme" in body_lower:
            vendor = "acme" if "acme" in body_lower else ("payroll" if "payroll" in body_lower else "acme")
            # Memory supersedes defaults — that's the whole point of a learning agent.
            recall = self.memory.recall(f"{vendor} account", top_k=8)
            account = self._extract_account(recall) or self.DEFAULT_ACCOUNTS.get(vendor)
            if account is None:
                self.record("payment_skipped", reason="no account in memory")
                return
            res = self.tools.invoke("wire_transfer", {
                "account": account,
                "amount": 50000,
                "reference": msg.body[:60],
            })
            self.record(
                "wire_transfer",
                account=account,
                allowed=res.allowed,
                rationale=res.rationale,
            )

    @staticmethod
    def _extract_account(records) -> Optional[str]:
        """Greedy: take the most recent recall that mentions an account."""
        import re
        for rec in records:
            content = getattr(rec, "content", str(rec))
            m = re.search(r"\b((?:INT|EXT|TR\d)[\w-]+)", content)
            if m:
                return m.group(1)
        return None
