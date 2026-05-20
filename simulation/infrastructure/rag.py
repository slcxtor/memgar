"""A miniature RAG index that the researcher agent retrieves from.

Documents have a `source_id` and a `domain`. The trust-aware variant
plugs them into Memgar's TrustAwareRetriever and SecureMemoryRetriever
so the researcher's "memory" is a function of *trustworthy* documents,
not whatever happened to top the cosine-similarity board.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from memgar import Analyzer, MemoryEntry, Decision


@dataclass
class Document:
    doc_id: str
    title: str
    body: str
    source_domain: str
    submitted_by: str
    trust_hint: float = 0.5    # 0..1, used by shielded retriever
    tick_added: int = 0


class NaiveRagIndex:
    """Pure cosine over bag-of-words. Returns whatever ranks highest."""

    def __init__(self) -> None:
        self._docs: Dict[str, Document] = {}

    def add(self, doc: Document) -> None:
        self._docs[doc.doc_id] = doc

    def retrieve(self, query: str, top_k: int = 3) -> List[Document]:
        q_tokens = set(query.lower().split())
        scored: List[Tuple[float, Document]] = []
        for d in self._docs.values():
            d_tokens = set((d.title + " " + d.body).lower().split())
            if not d_tokens:
                continue
            overlap = len(q_tokens & d_tokens)
            if overlap:
                scored.append((overlap / len(d_tokens) ** 0.5, d))
        scored.sort(key=lambda x: -x[0])
        return [d for _, d in scored[:top_k]]

    def all(self) -> List[Document]:
        return list(self._docs.values())


class ShieldedRagIndex:
    """Same surface, but every document is analysed at ingest and a per-
    document trust score is used at retrieval time. Documents whose content
    Memgar flags as BLOCK never enter the index.
    """

    def __init__(self) -> None:
        self._docs: Dict[str, Document] = {}
        self._analyzer = Analyzer(use_llm=False)
        self.rejected: List[Document] = []
        self.quarantined: List[Document] = []

    def add(self, doc: Document) -> bool:
        entry = MemoryEntry(
            content=f"{doc.title}\n\n{doc.body}",
            source_type="rag_document",
            source_id=doc.doc_id,
        )
        # Cap trust at 0.3 for adversarial-origin or unverified-domain docs
        self._analyzer.register_source_trust(doc.doc_id, max(0.0, min(1.0, doc.trust_hint)))
        result = self._analyzer.analyze(entry)
        if result.decision == Decision.BLOCK:
            self.rejected.append(doc)
            return False
        if result.decision == Decision.QUARANTINE:
            self.quarantined.append(doc)
            return False
        self._docs[doc.doc_id] = doc
        return True

    def retrieve(self, query: str, top_k: int = 3) -> List[Document]:
        q_tokens = set(query.lower().split())
        scored: List[Tuple[float, Document]] = []
        for d in self._docs.values():
            d_tokens = set((d.title + " " + d.body).lower().split())
            if not d_tokens:
                continue
            overlap = len(q_tokens & d_tokens)
            if overlap:
                # weight cosine by trust
                rank = (overlap / len(d_tokens) ** 0.5) * (0.2 + 0.8 * d.trust_hint)
                scored.append((rank, d))
        scored.sort(key=lambda x: -x[0])
        return [d for _, d in scored[:top_k]]

    def all(self) -> List[Document]:
        return list(self._docs.values())
