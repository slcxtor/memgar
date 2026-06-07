"""
Memgar Haystack Integration
===========================

Memory security for Haystack 2.x pipelines and document stores
(https://haystack.deepset.ai). Memory poisoning enters through:

  * ``DocumentStore.write_documents()`` — poisoned RAG documents.
  * ``ChatMessage`` objects fed to a generator / prompt builder.
  * Component outputs that flow back into the pipeline's chat history.

This adapter offers a delegating proxy for any document store, a
``ChatMessage`` scanner, and a drop-in Haystack ``Component`` that can be
wired as a firewall node in a pipeline — all on top of the framework-agnostic
``UniversalMemoryGuard`` (SecureMemoryStore by default).

Duck-typed: works with real ``haystack.dataclasses.Document`` /
``ChatMessage`` objects, plain dicts, or strings, and does not hard-require
haystack to be importable.

Usage::

    from memgar.integrations.haystack import (
        MemgarHaystackGuard, secure_document_store, MemgarFirewallComponent,
    )

    guard = MemgarHaystackGuard(on_threat="block")

    # (a) Wrap any DocumentStore so write_documents() scans each doc:
    store = secure_document_store(InMemoryDocumentStore())

    # (b) Scan a ChatMessage list before passing to a Generator:
    safe = guard.guard_chat_messages(history)

    # (c) Insert a firewall component in a Pipeline:
    pipeline.add_component("memgar", MemgarFirewallComponent())
    pipeline.connect("retriever.documents", "memgar.documents")
    pipeline.connect("memgar.documents", "prompt_builder.documents")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence

from .universal import MemoryBlockedError, UniversalMemoryGuard

logger = logging.getLogger(__name__)


@dataclass
class HaystackScanStats:
    documents_scanned: int = 0
    documents_dropped: int = 0
    messages_scanned: int = 0
    messages_dropped: int = 0


class MemgarHaystackThreatError(RuntimeError):
    """Raised when a poisoned doc/message is blocked before pipeline ingress."""

    def __init__(self, message: str, *, preview: str = "", risk_score: int = 0):
        super().__init__(message)
        self.preview = preview
        self.risk_score = risk_score


def _doc_content(doc: Any) -> Optional[str]:
    if isinstance(doc, str):
        return doc
    if isinstance(doc, dict):
        return doc.get("content") or doc.get("text")
    return getattr(doc, "content", None) or getattr(doc, "text", None)


def _set_doc_content(doc: Any, safe: str) -> Any:
    if isinstance(doc, str):
        return safe
    if isinstance(doc, dict):
        new = dict(doc)
        if "content" in new:
            new["content"] = safe
        elif "text" in new:
            new["text"] = safe
        else:
            new["content"] = safe
        return new
    if hasattr(doc, "model_copy"):
        try:
            return doc.model_copy(update={"content": safe})
        except Exception:
            pass
    try:
        doc.content = safe
    except Exception:
        pass
    return doc


def _msg_text(msg: Any) -> Optional[str]:
    if isinstance(msg, str):
        return msg
    if isinstance(msg, dict):
        return msg.get("content") or msg.get("text")
    # Haystack ChatMessage exposes .text (preferred) or .content (list of parts).
    if hasattr(msg, "text"):
        try:
            t = msg.text
            if isinstance(t, str):
                return t
        except Exception:
            pass
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                v = part.get("text") or part.get("content")
                if isinstance(v, str):
                    parts.append(v)
            else:
                v = getattr(part, "text", None) or getattr(part, "content", None)
                if isinstance(v, str):
                    parts.append(v)
        return "\n".join(parts) if parts else None
    return None


class MemgarHaystackGuard:
    """Security guard for Haystack pipelines — scans documents and chat
    messages at the framework boundary."""

    def __init__(
        self,
        on_threat: str = "block",
        *,
        memory_guard: Optional[UniversalMemoryGuard] = None,
        secure_store: Optional[Any] = None,
        agent_id: str = "haystack",
        **guard_kwargs: Any,
    ) -> None:
        self._on_threat = on_threat
        self._stats = HaystackScanStats()
        self._memory_guard = memory_guard or UniversalMemoryGuard(
            secure_store=secure_store,
            on_write_threat=on_threat,
            on_read_threat="drop" if on_threat == "block" else on_threat,
            on_tool_result_threat=on_threat,
            default_source_type="haystack_document",
            agent_id=agent_id,
            **guard_kwargs,
        )

    @property
    def memory_guard(self) -> UniversalMemoryGuard:
        return self._memory_guard

    @property
    def stats(self) -> HaystackScanStats:
        return self._stats

    # ------------------------------------------------------------------ scan
    def _scan_text(self, text: str, *, source_type: str, source_id: str
                   ) -> Optional[str]:
        if not text:
            return text
        try:
            protected = self._memory_guard.protect_write(
                text, source_type=source_type, source_id=source_id)
        except MemoryBlockedError as exc:
            risk = int(getattr(getattr(exc, "result", None), "risk_score", 0) or 0)
            raise MemgarHaystackThreatError(
                "Haystack content blocked before reaching the model",
                preview=text[:140], risk_score=risk) from exc
        if not getattr(protected, "allowed", True):
            return None
        safe = getattr(protected, "safe_content", None)
        return safe if (safe is not None and safe != text) else text

    # ------------------------------------------------------------- documents
    def guard_documents(self, documents: Sequence[Any]) -> List[Any]:
        out: List[Any] = []
        for i, doc in enumerate(documents):
            self._stats.documents_scanned += 1
            text = _doc_content(doc)
            if text is None:
                out.append(doc)
                continue
            safe = self._scan_text(
                text, source_type="haystack_document", source_id=f"doc{i}")
            if safe is None:
                self._stats.documents_dropped += 1
                continue
            out.append(doc if safe == text else _set_doc_content(doc, safe))
        return out

    # -------------------------------------------------------------- messages
    def guard_chat_messages(self, messages: Sequence[Any]) -> List[Any]:
        out: List[Any] = []
        for i, msg in enumerate(messages):
            self._stats.messages_scanned += 1
            text = _msg_text(msg)
            if text is None:
                out.append(msg)
                continue
            safe = self._scan_text(
                text, source_type="haystack_chat_message",
                source_id=f"msg{i}")
            if safe is None:
                self._stats.messages_dropped += 1
                continue
            if safe == text:
                out.append(msg)
            elif isinstance(msg, dict):
                new = dict(msg)
                if "content" in new:
                    new["content"] = safe
                else:
                    new["text"] = safe
                out.append(new)
            else:
                # Best-effort mutate. Haystack ChatMessage is a pydantic model;
                # use model_copy when available.
                if hasattr(msg, "model_copy"):
                    try:
                        out.append(msg.model_copy(update={"content": safe}))
                        continue
                    except Exception:
                        pass
                try:
                    msg.content = safe
                except Exception:
                    pass
                out.append(msg)
        return out

    # ---------------------------------------------------------- store proxy
    def secure_document_store(self, store: Any) -> Any:
        """Return a proxy that delegates everything to ``store`` but scans
        documents on ``write_documents``."""
        return _SecureDocumentStoreProxy(store, self)


class _SecureDocumentStoreProxy:
    """Delegating proxy that intercepts write_documents()."""

    def __init__(self, store: Any, guard: MemgarHaystackGuard) -> None:
        object.__setattr__(self, "_store", store)
        object.__setattr__(self, "_guard", guard)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._store, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_store", "_guard"):
            object.__setattr__(self, name, value)
        else:
            setattr(self._store, name, value)

    def write_documents(self, documents, *args, **kwargs):
        safe = self._guard.guard_documents(list(documents))
        return self._store.write_documents(safe, *args, **kwargs)


# ------------------------------------------------------------- pipeline node
def _make_component():
    """Return MemgarFirewallComponent. Defined lazily because the haystack
    decorator must succeed only when haystack is importable."""
    try:
        from haystack import component
    except Exception:
        return None

    @component
    class MemgarFirewallComponent:
        """Drop-in Haystack pipeline node: scans documents (and optional chat
        messages) and emits the cleaned lists. Use after a retriever / before
        a prompt builder."""

        def __init__(self, on_threat: str = "block") -> None:
            self._guard = MemgarHaystackGuard(on_threat=on_threat)

        @component.output_types(documents=list, messages=list)
        def run(self, documents: Optional[list] = None,
                messages: Optional[list] = None) -> dict:
            safe_docs = self._guard.guard_documents(documents or [])
            safe_msgs = self._guard.guard_chat_messages(messages or [])
            return {"documents": safe_docs, "messages": safe_msgs}

    return MemgarFirewallComponent


MemgarFirewallComponent = _make_component()


def secure_document_store(store: Any, **kwargs: Any) -> Any:
    """Convenience: wrap any document store with a default guard."""
    return MemgarHaystackGuard(**kwargs).secure_document_store(store)


def guard_documents(documents: Sequence[Any], **kwargs: Any) -> List[Any]:
    return MemgarHaystackGuard(**kwargs).guard_documents(documents)


def guard_chat_messages(messages: Sequence[Any], **kwargs: Any) -> List[Any]:
    return MemgarHaystackGuard(**kwargs).guard_chat_messages(messages)
