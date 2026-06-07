"""
Memgar Semantic Kernel Integration
==================================

Memory security for Microsoft Semantic Kernel agents and agent groups.

Semantic Kernel keeps conversational memory in a ``ChatHistory`` (a list of
``ChatMessageContent`` with ``role``/``content``) and runs plugin/kernel
functions whose results can feed back into that history. Untrusted content
enters via user/tool/function messages — the memory-poisoning ingress. This
adapter scans content before it is appended to history and offers a
function-invocation filter compatible with SK's filter pipeline, all through
the framework-agnostic UniversalMemoryGuard (SecureMemoryStore by default).

Duck-typed: works with ``ChatMessageContent`` objects, ``{"role","content"}``
dicts, or plain strings, and does not require semantic-kernel to be importable.

Usage::

    from memgar.integrations.semantic_kernel import MemgarSemanticKernelGuard

    guard = MemgarSemanticKernelGuard(on_threat="block")

    # (a) Wrap a ChatHistory so every appended message is scanned:
    history = guard.secure_chat_history(ChatHistory())
    history.add_user_message(untrusted_text)   # blocked/sanitized

    # (b) Register a function-invocation filter on the kernel:
    kernel.add_filter("function_invocation", guard.function_invocation_filter)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, List, Optional

from .universal import MemoryBlockedError, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class SemanticKernelScanStats:
    messages_scanned: int = 0
    messages_blocked: int = 0
    function_results_scanned: int = 0


class MemgarSemanticKernelThreatError(RuntimeError):
    """Raised when a poisoned message/result is blocked."""

    def __init__(self, message: str, *, preview: str = "", risk_score: int = 0):
        super().__init__(message)
        self.preview = preview
        self.risk_score = risk_score


def _content_of(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, dict):
        return str(message.get("content", ""))
    content = getattr(message, "content", None)
    return content if isinstance(content, str) else ("" if content is None else str(content))


class MemgarSemanticKernelGuard:
    """Security guard for Semantic Kernel chat history and function results."""

    def __init__(
        self,
        on_threat: str = "block",
        *,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        **guard_kwargs: Any,
    ) -> None:
        self._on_threat = on_threat
        self._stats = SemanticKernelScanStats()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="semantic_kernel_message",
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        return self._memory_guard

    @property
    def stats(self) -> SemanticKernelScanStats:
        return self._stats

    # ------------------------------------------------------------------ scan
    def guard_message(self, content: str, *, source_id: str = "sk_message") -> Optional[str]:
        """Return safe content, or None if it must be dropped.

        Raises MemgarSemanticKernelThreatError when on_threat='block'."""
        if not content:
            return content
        self._stats.messages_scanned += 1
        try:
            protected = self._memory_guard.protect_write(
                content,
                source_type="semantic_kernel_message",
                source_id=source_id,
            )
        except MemoryBlockedError as exc:
            self._stats.messages_blocked += 1
            risk = int(getattr(getattr(exc, "result", None), "risk_score", 0) or 0)
            raise MemgarSemanticKernelThreatError(
                "Semantic Kernel message blocked",
                preview=content[:140],
                risk_score=risk,
            ) from exc
        if not getattr(protected, "allowed", True):
            self._stats.messages_blocked += 1
            return None
        return getattr(protected, "safe_content", None) or content

    def guard_messages(self, messages: List[Any], *, source_id: str = "sk") -> List[Any]:
        safe: List[Any] = []
        for i, m in enumerate(messages):
            text = _content_of(m)
            result = self.guard_message(text, source_id=f"{source_id}[{i}]") if text else text
            if result is None:
                continue
            safe.append(m if result == text else _replace(m, result))
        return safe

    # --------------------------------------------------------- chat history
    def secure_chat_history(self, history: Any) -> Any:
        """Wrap a ChatHistory so add_* methods scan content before appending.

        Returns a proxy that delegates everything to the underlying history but
        intercepts the add_* methods. A proxy (rather than monkey-patching the
        instance) is required because Semantic Kernel's ChatHistory is a Pydantic
        model that rejects ``setattr`` of new method attributes."""
        return _SecureChatHistoryProxy(history, self)


class _SecureChatHistoryProxy:
    """Delegating proxy that scans content on add_user/system/message."""

    _INTERCEPT = ("add_user_message", "add_message", "add_system_message")

    def __init__(self, history: Any, guard: "MemgarSemanticKernelGuard") -> None:
        object.__setattr__(self, "_history", history)
        object.__setattr__(self, "_guard", guard)

    def _secured_add(self, method_name: str, content: Any, *args: Any, **kwargs: Any) -> Any:
        original = getattr(self._history, method_name)
        text = _content_of(content)
        safe = self._guard.guard_message(text, source_id=f"history.{method_name}")
        if safe is None:
            return None  # dropped (warn/log mode); blocked mode raises in guard_message
        new_content = content if safe == text else _replace(content, safe)
        return original(new_content, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        if name in _SecureChatHistoryProxy._INTERCEPT:
            return lambda content, *a, **k: self._secured_add(name, content, *a, **k)
        return getattr(self._history, name)  # delegate everything else (messages, etc.)

    def __iter__(self):
        return iter(self._history)

    def __len__(self):
        return len(self._history)

    # --------------------------------------------------- function invocation
    async def function_invocation_filter(self, context: Any, next: Callable) -> Any:
        """SK function-invocation filter: scans the function result before it can
        feed back into the conversation/memory. Register via
        ``kernel.add_filter("function_invocation", guard.function_invocation_filter)``."""
        await next(context)
        self._stats.function_results_scanned += 1
        result = getattr(context, "result", None)
        if result is None:
            return
        text = _content_of(result) or str(getattr(result, "value", "") or "")
        if not text:
            return
        safe = self.guard_message(text, source_id="function_result")
        if safe is not None and safe != text:
            # Replace the sanitized result value where the framework allows it.
            if hasattr(result, "value"):
                try:
                    result.value = safe
                except Exception:
                    pass


def _replace(message: Any, safe: str) -> Any:
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


def guard_chat_history(history: Any, **kwargs: Any) -> Any:
    """Convenience: wrap a ChatHistory with a default guard."""
    return MemgarSemanticKernelGuard(**kwargs).secure_chat_history(history)
