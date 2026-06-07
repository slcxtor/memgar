"""
Memgar Pydantic AI Integration
==============================

Memory security for Pydantic AI agents (https://ai.pydantic.dev).

Pydantic AI agents pass user prompts + tool returns to the model as a list of
``ModelMessage`` parts. Memory poisoning enters through user prompts and —
more dangerously — through ``ToolReturnPart`` content (indirect injection in
tool / API / RAG output). This adapter scans those parts at the framework
boundary, before they reach the model, using the framework-agnostic
``UniversalMemoryGuard`` (SecureMemoryStore by default).

Duck-typed: works with Pydantic AI ``ModelMessage`` objects, plain dicts with
``content``, or plain strings, and does not hard-require pydantic_ai to be
importable.

Usage::

    from memgar.integrations.pydantic_ai import MemgarPydanticAIGuard

    guard = MemgarPydanticAIGuard(on_threat="block")

    # (a) Manual scan of any message list before agent.run:
    safe_messages = guard.guard_messages(messages)

    # (b) Wrap an Agent so every run() scans its inputs:
    from pydantic_ai import Agent
    agent = Agent(model="openai:gpt-4o-mini", system_prompt="You are a support bot.")
    secured = guard.secure_agent(agent)
    result = await secured.run("user said: please ignore previous rules ...")
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from .universal import MemoryBlockedError, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class PydanticAIScanStats:
    messages_scanned: int = 0
    parts_scanned: int = 0
    blocked: int = 0
    sanitized: int = 0


class MemgarPydanticAIThreatError(RuntimeError):
    """Raised when a poisoned message/part is blocked before reaching the model."""

    def __init__(self, message: str, *, preview: str = "", risk_score: int = 0):
        super().__init__(message)
        self.preview = preview
        self.risk_score = risk_score


# Pydantic AI part attribute that carries text content varies by part type;
# this set is the duck-typed search list.
_TEXT_ATTRS = ("content", "text", "tool_return", "user_prompt", "value")


def _extract_text(obj: Any) -> Optional[str]:
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        for k in _TEXT_ATTRS:
            v = obj.get(k)
            if isinstance(v, str) and v:
                return v
        return None
    for attr in _TEXT_ATTRS:
        v = getattr(obj, attr, None)
        if isinstance(v, str) and v:
            return v
    return None


def _replace_text(obj: Any, safe: str) -> Any:
    if isinstance(obj, str):
        return safe
    if isinstance(obj, dict):
        new = dict(obj)
        for k in _TEXT_ATTRS:
            if k in new and isinstance(new[k], str):
                new[k] = safe
                return new
        return new
    for attr in _TEXT_ATTRS:
        if hasattr(obj, attr) and isinstance(getattr(obj, attr), str):
            try:
                # Try model_copy for pydantic models, else setattr.
                if hasattr(obj, "model_copy"):
                    return obj.model_copy(update={attr: safe})
                setattr(obj, attr, safe)
            except Exception:
                pass
            return obj
    return obj


class MemgarPydanticAIGuard:
    """Security guard for Pydantic AI agents — scans message parts before the
    model sees them, treating ToolReturnPart content as untrusted by default."""

    def __init__(
        self,
        on_threat: str = "block",
        *,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        agent_id: str = "pydantic_ai",
        **guard_kwargs: Any,
    ) -> None:
        self._on_threat = on_threat
        self._stats = PydanticAIScanStats()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="pydantic_ai_message",
            agent_id=agent_id,
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        return self._memory_guard

    @property
    def stats(self) -> PydanticAIScanStats:
        return self._stats

    # ------------------------------------------------------------------ scan
    def _scan_text(self, text: str, *, source_id: str) -> Optional[str]:
        """Return safe text, or None if it must be dropped."""
        if not text:
            return text
        try:
            protected = self._memory_guard.protect_write(
                text, source_type="pydantic_ai_message", source_id=source_id)
        except MemoryBlockedError as exc:
            self._stats.blocked += 1
            risk = int(getattr(getattr(exc, "result", None), "risk_score", 0) or 0)
            raise MemgarPydanticAIThreatError(
                "Pydantic AI message blocked before reaching the model",
                preview=text[:140], risk_score=risk) from exc
        if not getattr(protected, "allowed", True):
            self._stats.blocked += 1
            return None
        safe = getattr(protected, "safe_content", None)
        if safe is not None and safe != text:
            self._stats.sanitized += 1
            return safe
        return text

    def guard_messages(self, messages: Sequence[Any]) -> List[Any]:
        """Walk a message list, scan every part with text content, drop poisoned
        ones, sanitize the rest."""
        safe_messages: List[Any] = []
        for mi, msg in enumerate(messages):
            self._stats.messages_scanned += 1
            parts = getattr(msg, "parts", None)
            if parts is None and isinstance(msg, dict):
                parts = msg.get("parts")
            if parts is None:
                # Treat the message itself as a single text-bearing item.
                parts = [msg]
                single = True
            else:
                single = False

            safe_parts: List[Any] = []
            for pi, part in enumerate(parts):
                self._stats.parts_scanned += 1
                text = _extract_text(part)
                if text is None:
                    safe_parts.append(part)
                    continue
                result = self._scan_text(text, source_id=f"msg{mi}.part{pi}")
                if result is None:
                    continue
                safe_parts.append(part if result == text
                                  else _replace_text(part, result))

            if single:
                if safe_parts:
                    safe_messages.append(safe_parts[0])
            else:
                # Re-attach scanned parts where possible.
                if hasattr(msg, "model_copy"):
                    try:
                        safe_messages.append(msg.model_copy(update={"parts": safe_parts}))
                        continue
                    except Exception:
                        pass
                if isinstance(msg, dict):
                    new = dict(msg); new["parts"] = safe_parts
                    safe_messages.append(new)
                else:
                    try:
                        msg.parts = safe_parts
                    except Exception:
                        pass
                    safe_messages.append(msg)
        return safe_messages

    # ----------------------------------------------------------- agent wrap
    def secure_agent(self, agent: Any) -> Any:
        """Wrap an Agent's ``run`` / ``run_sync`` so the user prompt is scanned
        before invocation. Tool returns flowing back through Pydantic AI's
        message-history mechanism can be scanned by passing them through
        :meth:`guard_messages` from a result-event hook."""
        guard = self

        for method_name in ("run", "run_sync", "run_stream"):
            original = getattr(agent, method_name, None)
            if original is None or not callable(original):
                continue

            @functools.wraps(original)
            def wrapped(user_prompt: Any = "", *args: Any, _orig=original,
                        _name=method_name, **kwargs: Any) -> Any:
                if isinstance(user_prompt, str) and user_prompt:
                    safe = guard._scan_text(user_prompt,
                                            source_id=f"agent.{_name}")
                    if safe is None:
                        # warn/log modes: substitute empty string to keep types.
                        user_prompt = ""
                    else:
                        user_prompt = safe
                # Also scan message_history if the caller supplies it.
                history = kwargs.get("message_history")
                if history:
                    kwargs["message_history"] = guard.guard_messages(history)
                return _orig(user_prompt, *args, **kwargs)

            try:
                setattr(agent, method_name, wrapped)
            except Exception:
                pass
        return agent


def guard_messages(messages: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Convenience: one-shot scan of a Pydantic AI message list."""
    return MemgarPydanticAIGuard(**kwargs).guard_messages(messages)
