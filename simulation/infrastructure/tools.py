"""Tool runtime used by the finance agent.

When unshielded the agent will dutifully execute whatever its memory
told it to. When shielded the call goes through ToolUseGuard, which
inspects the parameters and refuses obviously dangerous calls
(unknown payment account, exfil URL, foreign domain, etc.).
"""

from __future__ import annotations

import re
import urllib.parse
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


def _extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s)>\"']+", text or "")


def _is_outbound_url(url: str) -> bool:
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return True
    return not (host.endswith("internal.corp") or host == "localhost")


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
        elif tool == "markdown_render":
            # Naive: render markdown by *fetching every image src*.
            # That is precisely what M365 Copilot / ChatGPT do, and that
            # is the SpAIware / EchoLeak exfil channel.
            for url in _extract_urls(str(params.get("markdown", ""))):
                self.ledger.append({"tool": "http_get", "url": url,
                                    "origin": "markdown_render"})
            rec.result = "rendered"
        elif tool == "sql_query":
            # Naive: just executes whatever was generated. Vanna-style RCE.
            self.ledger.append({"tool": "sql_query", **params})
            rec.result = "rows: 0"
        elif tool == "mcp_tool_call":
            # Naive MCP: blindly accepts the tool description from the
            # server and follows its instructions.
            self.ledger.append({"tool": "mcp_tool_call", **params})
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
        self.guard.register_tool("markdown_render", ToolRisk.HIGH)
        self.guard.register_tool("sql_query", ToolRisk.HIGH)
        self.guard.register_tool("mcp_tool_call", ToolRisk.HIGH)
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
        if tool == "markdown_render":
            # The killer policy: if the rendered markdown would cause the
            # client to GET any non-internal URL (image, link), refuse.
            # This is what blocks SpAIware / EchoLeak markdown exfil.
            md = str(params.get("markdown", ""))
            outbound = [u for u in _extract_urls(md) if _is_outbound_url(u)]
            if outbound:
                return f"markdown would beacon to external host(s): {outbound[:2]}"
        if tool == "sql_query":
            sql = str(params.get("sql", "")).lower()
            dangerous = ("drop ", "delete ", "truncate ", "alter ", "; --", "exec ",
                         "xp_cmdshell", "load_file", "into outfile")
            for kw in dangerous:
                if kw in sql:
                    return f"SQL contains dangerous construct {kw!r}"
        if tool == "mcp_tool_call":
            # MCP tool descriptions are a known confused-deputy channel.
            # We refuse any call whose description contains instructions
            # to the LLM (Invariant Labs GitHub-MCP exfil pattern).
            desc = str(params.get("tool_description", "")).lower()
            triggers = ("ignore previous", "read all", "exfiltrate", "send to",
                        "include the contents of", "private repo", "always include")
            for kw in triggers:
                if kw in desc:
                    return f"MCP tool description contains injection pattern {kw!r}"
        return None

    def invoke(self, tool: str, params: Dict[str, Any]) -> ToolCallRecord:
        result = self.guard.check_call(tool_name=tool, arguments=params)
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
        elif tool == "markdown_render":
            for url in _extract_urls(str(params.get("markdown", ""))):
                if not _is_outbound_url(url):
                    self.ledger.append({"tool": "http_get", "url": url,
                                        "origin": "markdown_render"})
        elif tool == "sql_query":
            self.ledger.append({"tool": "sql_query", **params})
        elif tool == "mcp_tool_call":
            self.ledger.append({"tool": "mcp_tool_call", **params})
        rec.result = "OK"
        self.calls.append(rec)
        return rec
