"""Researcher agent.

Answers questions by RAG: it pulls top-k documents from an index and
summarises them into its persistent memory. The attack surface is the
index: anyone who can add documents (a public wiki ingest, a customer
support knowledge base, a vendor portal) can poison its answers.
"""

from __future__ import annotations

from typing import List, Optional

from .base import BaseAgent


class ResearcherAgent(BaseAgent):
    role = "researcher"

    def __init__(self, *args, rag, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.rag = rag

    def step(self) -> None:
        for msg in self.world.drain(self.name):
            if msg.kind != "request":
                # Anything that arrives as a free-form note (forwarded mail,
                # bus message, etc.) is absorbed into memory — that's how a
                # real research-summarising agent behaves.
                self._absorb(msg, source_type=msg.channel)
                self.record("absorb", sender=msg.sender, channel=msg.channel)
                continue
            if msg.kind == "request":
                hits = self.rag.retrieve(msg.body, top_k=3)
                # Realistic LLM-style summarisation: pull the substantive
                # content of each hit into the answer so an attacker who
                # poisons a doc actually sees the payload appear downstream.
                # Realistic summarisation length — enough that an embedded
                # markdown image URL or instruction inside a doc body still
                # surfaces in the summary (where downstream agents can act
                # on it). 160 chars truncates exactly the payload region.
                parts = [f"{h.title}: {h.body[:400]}" for h in hits]
                summary = " | ".join(parts) or "no hits"
                rec = self.memory.write(
                    f"Q: {msg.body[:80]} A: {summary}",
                    source_type="rag_summary",
                    source_id=msg.sender,
                    tick=self.world.tick,
                )
                self.record(
                    "rag_answer",
                    query=msg.body[:80],
                    sources=[h.doc_id for h in hits],
                    accepted=getattr(rec, "accepted", True),
                )

    def answer(self, query: str) -> List[str]:
        hits = self.rag.retrieve(query, top_k=3)
        return [f"[{h.doc_id}] {h.title}: {h.body[:200]}" for h in hits]
