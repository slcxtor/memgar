"""
Memgar LangGraph Integration
============================

Memory/state security for LangGraph agent graphs and multi-agent networks.

LangGraph agents share a typed ``state`` (usually a ``messages`` list updated
by nodes through reducers) and persist it via checkpointers. Untrusted content
enters that shared state from tool results, retrieval nodes, sub-agents and
external messages — the memory-poisoning ingress. This adapter scans messages
before they merge into state, using the framework-agnostic UniversalMemoryGuard
(SecureMemoryStore by default: policy, DLP, audit, block/sanitize).

It is duck-typed: it works whether messages are langchain_core ``BaseMessage``
objects, ``{"role", "content"}`` dicts, or plain strings, and it does not
require langgraph to be importable.

Usage::

    from memgar.integrations.langgraph import MemgarLangGraphGuard

    guard = MemgarLangGraphGuard(on_threat="block")

    # (a) Insert a firewall node after tool/retrieval nodes:
    graph.add_node("memgar_firewall", guard.firewall_node)
    graph.add_edge("tools", "memgar_firewall")
    graph.add_edge("memgar_firewall", "agent")

    # (b) Or wrap any node so its emitted messages are scanned:
    graph.add_node("tools", guard.guard_node(tool_node))
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from .universal import MemoryBlockedError, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class LangGraphScanStats:
    messages_scanned: int = 0
    messages_blocked: int = 0
    nodes_guarded: int = 0


class MemgarLangGraphThreatError(RuntimeError):
    """Raised when a poisoned message is blocked before entering graph state."""

    def __init__(self, message: str, *, preview: str = "", risk_score: int = 0):
        super().__init__(message)
        self.preview = preview
        self.risk_score = risk_score


def _message_content(message: Any) -> str:
    """Extract text from a BaseMessage, a {'content': ...} dict, or a string."""
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        return str(message.get("content", ""))
    content = getattr(message, "content", None)
    return content if isinstance(content, str) else ("" if content is None else str(content))


def _with_content(message: Any, safe: str) -> Any:
    """Return a copy of message with its text replaced (sanitized writes)."""
    if isinstance(message, str):
        return safe
    if isinstance(message, dict):
        updated = dict(message)
        updated["content"] = safe
        return updated
    for cloner in ("model_copy", "copy"):
        fn = getattr(message, cloner, None)
        if fn is not None:
            try:
                return fn(update={"content": safe})
            except Exception:
                pass
    try:
        message.content = safe
    except Exception:
        pass
    return message


class MemgarLangGraphGuard:
    """Security guard for LangGraph shared state / message channels."""

    def __init__(
        self,
        on_threat: str = "block",
        *,
        messages_key: str = "messages",
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ) -> None:
        self._on_threat = on_threat
        self._messages_key = messages_key
        self._stats = LangGraphScanStats()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="langgraph_message",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        return self._memory_guard

    @property
    def stats(self) -> LangGraphScanStats:
        return self._stats

    # ------------------------------------------------------------------ scan
    def _scan_one(self, message: Any, *, source_id: str) -> Optional[Any]:
        """Return the (possibly sanitized) message, or None if it must be dropped.

        Raises MemgarLangGraphThreatError when on_threat='block'."""
        content = _message_content(message)
        if not content:
            return message
        self._stats.messages_scanned += 1
        try:
            protected = self._memory_guard.protect_write(
                content,
                source_type="langgraph_message",
                source_id=source_id,
            )
        except MemoryBlockedError as exc:
            self._stats.messages_blocked += 1
            risk = int(getattr(getattr(exc, "result", None), "risk_score", 0) or 0)
            raise MemgarLangGraphThreatError(
                "LangGraph message blocked before entering state",
                preview=content[:140],
                risk_score=risk,
            ) from exc

        if not getattr(protected, "allowed", True):
            # warn/log/drop modes: drop the message from state.
            self._stats.messages_blocked += 1
            return None
        safe = getattr(protected, "safe_content", None)
        if safe is not None and safe != content:
            return _with_content(message, safe)
        return message

    def guard_messages(self, messages: List[Any], *, source_id: str = "node") -> List[Any]:
        """Scan a list of messages; drop/block poisoned ones, sanitize the rest."""
        if not messages:
            return messages
        safe: List[Any] = []
        for i, m in enumerate(messages):
            result = self._scan_one(m, source_id=f"{source_id}[{i}]")
            if result is not None:
                safe.append(result)
        return safe

    def guard_state_update(self, update: Any, *, source_id: str = "node") -> Any:
        """Scan the messages inside a node's returned partial-state update."""
        if isinstance(update, dict) and self._messages_key in update:
            msgs = update[self._messages_key]
            if isinstance(msgs, list):
                cleaned = self.guard_messages(msgs, source_id=source_id)
            else:
                cleaned = self._scan_one(msgs, source_id=source_id)
                cleaned = [] if cleaned is None else cleaned
            new_update = dict(update)
            new_update[self._messages_key] = cleaned
            return new_update
        return update

    # ----------------------------------------------------------------- nodes
    def guard_node(self, node: Callable[..., Any]) -> Callable[..., Any]:
        """Wrap a node so the messages it emits are scanned before merging."""
        self._stats.nodes_guarded += 1

        @functools.wraps(node)
        def wrapped(state: Any, *args: Any, **kwargs: Any) -> Any:
            update = node(state, *args, **kwargs)
            return self.guard_state_update(update, source_id=getattr(node, "__name__", "node"))

        return wrapped

    def firewall_node(self, state: Any) -> Dict[str, Any]:
        """A standalone graph node: scans state[messages] and returns the cleaned
        list. Insert after tool/retrieval/sub-agent nodes."""
        if isinstance(state, dict) and self._messages_key in state:
            msgs = state[self._messages_key]
            if isinstance(msgs, list):
                return {self._messages_key: self.guard_messages(msgs, source_id="firewall")}
        return {}


def guard_graph_messages(messages: List[Any], **kwargs: Any) -> List[Any]:
    """Convenience: one-shot scan of a message list."""
    return MemgarLangGraphGuard(**kwargs).guard_messages(messages)
