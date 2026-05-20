"""Tool runtime used by the finance agent.

When unshielded the agent will dutifully execute whatever its memory
told it to. When shielded the call goes through ToolUseGuard, which
inspects the parameters and refuses obviously dangerous calls
(unknown payment account, exfil URL, foreign domain, etc.).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from memgar.tool_use_guard import ToolUseGuard, ToolRisk, ToolDecision


# Approved internal payment accounts. Anything else is suspect.
APPROVED_ACCOUNTS = {"INT-PAYROLL-001", "INT-VENDORS-001", "INT-TAX-001"}


@dataclass
class ToolCallRecord:
    tool: str
    params: Dict[str, Any]
    allowed: bool
    rationale: str = ""
    result: Optional[Any] = None
    risk: int = 0


class NaiveToolRuntime:
    """No checks. Just executes whatever the agent asked for."""

    def __init__(self) -> None:
        self.calls: List[ToolCallRecord] = []
        self.ledger: List[Dict[str, Any]] = []  # observable side-effects

    def invoke(self, tool: str, params: Dict[str, Any]) -> ToolCallRecord:
        rec = ToolCallRecord(tool=tool, params=params, allowed=True)
        if tool == "wire_transfer":
            self.ledger.append({"tool": "wire_transfer", **params})
            rec.result = "OK"
        elif tool == "send_email":
            self.ledger.append({"tool": "send_email", **params})
            rec.result = "OK"
        elif tool == "http_get":
            self.ledger.append({"tool": "http_get", **params})
            rec.result = "200 OK"
        elif tool == "grant_role":
            self.ledger.append({"tool": "grant_role", **params})
            rec.result = "OK"
        else:
            rec.result = "OK"
        self.calls.append(rec)
        return rec


class ShieldedToolRuntime:
    """ToolUseGuard + a tiny policy layer for the demo."""

    def __init__(self) -> None:
        self.guard = ToolUseGuard()
        self.guard.register_tool("wire_transfer", ToolRisk.CRITICAL)
        self.guard.register_tool("send_email", ToolRisk.HIGH)
        self.guard.register_tool("http_get", ToolRisk.MEDIUM)
        self.guard.register_tool("grant_role", ToolRisk.CRITICAL)
        self.calls: List[ToolCallRecord] = []
        self.ledger: List[Dict[str, Any]] = []
        self.blocked: List[ToolCallRecord] = []

    def _policy_check(self, tool: str, params: Dict[str, Any]) -> Optional[str]:
        # Application-layer policy on top of memgar's content scan.
        if tool == "wire_transfer":
            target = str(params.get("account", "")).strip()
            if target not in APPROVED_ACCOUNTS:
                return f"unknown payment account {target!r}"
        if tool == "send_email":
            to = str(params.get("to", ""))
            if "@" in to and not to.endswith("@internal.corp"):
                return f"outbound email to external address {to}"
        if tool == "http_get":
            url = str(params.get("url", ""))
            if re.search(r"https?://(?!.*internal\.corp)", url):
                return f"egress to non-internal host: {url}"
        if tool == "grant_role":
            if params.get("role") in {"admin", "root", "superuser"}:
                return "elevation to administrator role"
        return None

    def invoke(self, tool: str, params: Dict[str, Any]) -> ToolCallRecord:
        result = self.guard.check_call(agent_id="finance", tool_name=tool, parameters=params)
        rec = ToolCallRecord(
            tool=tool,
            params=params,
            allowed=(result.decision != ToolDecision.BLOCK),
            rationale=(result.rationale or ""),
            risk=int(result.risk_score or 0),
        )

        # Additional application policy
        policy_reason = self._policy_check(tool, params)
        if policy_reason:
            rec.allowed = False
            rec.rationale = (rec.rationale + " | " if rec.rationale else "") + policy_reason

        if not rec.allowed:
            self.blocked.append(rec)
            self.calls.append(rec)
            return rec

        if tool == "wire_transfer":
            self.ledger.append({"tool": "wire_transfer", **params})
        elif tool == "send_email":
            self.ledger.append({"tool": "send_email", **params})
        elif tool == "http_get":
            self.ledger.append({"tool": "http_get", **params})
        elif tool == "grant_role":
            self.ledger.append({"tool": "grant_role", **params})
        rec.result = "OK"
        self.calls.append(rec)
        return rec
