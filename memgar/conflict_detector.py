"""Memory conflict detection.

Flags pairs of stored memories that share a topic but contain opposing
polarity indicators (negations, antonyms of common instruction verbs).
A contradiction between two stored memories is a signal that one of
them was poisoned, since legitimate updates usually supersede rather
than directly contradict prior context.

If memory A says ``always X`` and memory B says ``never X``, downstream
queries will retrieve whichever has the higher trust weight, and the
agent will then defend an instruction the user never gave. Detecting
the contradiction at retrieval time lets us surface the conflict
before the agent acts on the poisoned half.

Heuristic-only. No NLP / NLI dependency — uses regex polarity probes
and (when available) sentence-transformers cosine similarity to gate
the polarity check to memory pairs that are actually about the same
topic. Designed to run in the retrieval path on the top-K memories
returned for a query, not on the full store.

Usage::

    from memgar.conflict_detector import ConflictDetector

    detector = ConflictDetector()
    conflicts = detector.scan([
        "User always wants verbose responses.",
        "User never wants verbose responses — keep it short.",
    ])
    for c in conflicts:
        print(c.summary, c.confidence)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


@dataclass
class ConflictReport:
    """A flagged contradiction between two memories."""
    memory_a_index: int
    memory_b_index: int
    memory_a_preview: str
    memory_b_preview: str
    topic_similarity: float
    polarity_pair: Tuple[str, str]
    confidence: float
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "memory_a_index": self.memory_a_index,
            "memory_b_index": self.memory_b_index,
            "memory_a_preview": self.memory_a_preview,
            "memory_b_preview": self.memory_b_preview,
            "topic_similarity": round(self.topic_similarity, 3),
            "polarity_pair": list(self.polarity_pair),
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
        }


# Polarity pairs the detector probes for. (a_terms, b_terms) — content
# that contains any term from `a_terms` is in polarity A. Membership in
# A and B simultaneously is allowed; the conflict requires that
# memory A is purely polarity A and memory B is purely polarity B.
# Single-word lemmas are matched with optional `-s | -ed | -ing | -d`
# inflections so real prose ("user prefers", "User remembers", "Memory
# stored") matches the same as the bare lemma. Multi-word phrases are
# matched literally (no inflection unfolding).
_POLARITY_PAIRS: List[Tuple[Tuple[str, ...], Tuple[str, ...]]] = [
    # Frequency / persistence flips — the textbook memory-instruction shape
    (("always", "must always", "every time"),
     ("never", "must never", "do not", "don't", "do n't")),
    # Preference flips
    (("prefer", "like", "want"),
     ("dislike", "do not prefer", "doesn't want", "does not want")),
    # Approval state flips
    (("approve", "allow", "permit"),
     ("reject", "deny", "forbid")),
    # Trust flips
    (("trust", "verified"),
     ("distrust", "untrusted", "do not trust", "compromised")),
    # Enable/disable
    (("enable", "activate", "turn on"),
     ("disable", "deactivate", "turn off")),
    # Remember/forget
    (("remember", "store", "keep", "retain"),
     ("forget", "discard", "delete this", "ignore this")),
]

# Single-token English inflection suffix probe (s, es, ed, ied, ing).
# `(?:s|es|ed|ing|d|ied)?` after a lemma — `\bprefer(?:s|ed|...)\b` —
# matches prefer / prefers / preferred / preferring / preferring / preferd
# without bloating each lemma list. Kept ASCII-only on purpose; Turkish
# verb inflection is out of scope here (memgar's L1 patterns already
# carry the locale-specific phrasings).
_INFLECTION_SUFFIX = r"(?:s|es|ed|ing|d|ied)?"


def _polarity_alternation(terms: Tuple[str, ...]) -> str:
    """Build an alternation regex from a polarity term list.

    Single-token lemmas get the optional inflection suffix appended;
    multi-word phrases are matched literally to avoid surprising matches
    inside phrases like "do not prefers".
    """
    parts = []
    for t in terms:
        esc = re.escape(t)
        if " " in t:
            parts.append(esc)
        else:
            parts.append(esc + _INFLECTION_SUFFIX)
    return r"\b(?:" + "|".join(parts) + r")\b"


def _compile_polarity(pairs: Sequence[Tuple[Tuple[str, ...], Tuple[str, ...]]]):
    compiled = []
    for a_terms, b_terms in pairs:
        a_re = re.compile(_polarity_alternation(a_terms), re.IGNORECASE)
        b_re = re.compile(_polarity_alternation(b_terms), re.IGNORECASE)
        compiled.append((a_re, b_re, a_terms[0], b_terms[0]))
    return compiled


_COMPILED_POLARITY = _compile_polarity(_POLARITY_PAIRS)


class ConflictDetector:
    """Detect contradictory memory pairs via topic+polarity matching.

    Args:
        topic_similarity_threshold: Minimum cosine similarity for two
            memories to be considered "about the same topic". Below this,
            opposing-polarity terms are not treated as a conflict.
            Default 0.55.
        use_embeddings: When True, gate the polarity check with cosine
            similarity from `memgar.similarity_layer`. When False, fall
            back to a Jaccard token-overlap proxy that needs no model.
        min_overlap_tokens: When `use_embeddings=False`, the minimum
            number of overlapping content tokens to consider two
            memories on-topic. Default 3.
    """

    def __init__(
        self,
        topic_similarity_threshold: Optional[float] = None,
        use_embeddings: bool = True,
        min_overlap_tokens: int = 3,
    ) -> None:
        # Two threshold regimes — embeddings give 0.6–0.9 cosine for same-topic
        # paraphrases, Jaccard token overlap typically sits at 0.3–0.5. Letting
        # callers pass a single value would force one mode to be wrong; we
        # instead pick a sensible default per mode unless the caller overrides.
        self.use_embeddings = bool(use_embeddings)
        self.min_overlap_tokens = int(min_overlap_tokens)
        self._embedder: Any = None
        if self.use_embeddings:
            try:
                from memgar.similarity_layer import get_global_layer
                self._embedder = get_global_layer()
            except Exception as exc:
                logger.debug("ConflictDetector: embeddings unavailable (%s)", exc)
                self._embedder = None
        if topic_similarity_threshold is None:
            self.topic_threshold = 0.55 if self._embedder is not None else 0.30
        else:
            self.topic_threshold = float(topic_similarity_threshold)

    def _topic_similarity(self, text_a: str, text_b: str) -> float:
        if self._embedder is not None:
            try:
                emb_a = self._embedder.encode(text_a)
                emb_b = self._embedder.encode(text_b)
                if emb_a is not None and emb_b is not None:
                    import numpy as _np
                    a = _np.asarray(emb_a).flatten()
                    b = _np.asarray(emb_b).flatten()
                    na = float(_np.linalg.norm(a))
                    nb = float(_np.linalg.norm(b))
                    if na > 0 and nb > 0:
                        return float(_np.dot(a, b) / (na * nb))
            except Exception:
                pass
        # Jaccard fallback — lowercased token sets, drop stopwords-ish
        ta = set(re.findall(r"\w+", text_a.lower())) - _STOPWORDS
        tb = set(re.findall(r"\w+", text_b.lower())) - _STOPWORDS
        if not ta or not tb:
            return 0.0
        inter = ta & tb
        if len(inter) < self.min_overlap_tokens:
            return 0.0
        return len(inter) / len(ta | tb)

    def _polarity_clash(self, text_a: str, text_b: str) -> Optional[Tuple[str, str]]:
        for a_re, b_re, a_label, b_label in _COMPILED_POLARITY:
            a_has_a = bool(a_re.search(text_a))
            a_has_b = bool(b_re.search(text_a))
            b_has_a = bool(a_re.search(text_b))
            b_has_b = bool(b_re.search(text_b))
            # Conflict requires memory A pure-A and memory B pure-B
            # (or symmetric: pure-B vs pure-A). Memories that contain
            # both polarities are already self-contradictory — that's a
            # different shape and not flagged here.
            if a_has_a and not a_has_b and b_has_b and not b_has_a:
                return (a_label, b_label)
            if a_has_b and not a_has_a and b_has_a and not b_has_b:
                return (b_label, a_label)
        return None

    def check_pair(
        self,
        memory_a: str,
        memory_b: str,
        index_a: int = 0,
        index_b: int = 1,
    ) -> Optional[ConflictReport]:
        """Return a ConflictReport if A and B contradict, else None."""
        if not memory_a or not memory_b:
            return None
        sim = self._topic_similarity(memory_a, memory_b)
        if sim < self.topic_threshold:
            return None
        polarity = self._polarity_clash(memory_a, memory_b)
        if polarity is None:
            return None
        # Confidence rises with topic overlap; clamp to [0.5, 0.95]
        conf = max(0.5, min(0.95, sim * 0.95 + 0.10))
        return ConflictReport(
            memory_a_index=index_a,
            memory_b_index=index_b,
            memory_a_preview=memory_a[:120],
            memory_b_preview=memory_b[:120],
            topic_similarity=sim,
            polarity_pair=polarity,
            confidence=conf,
            summary=(
                f"Memory #{index_a} asserts '{polarity[0]}' while "
                f"memory #{index_b} asserts '{polarity[1]}' on the same topic "
                f"(similarity={sim:.2f})."
            ),
        )

    def scan(self, memories: Sequence[str]) -> List[ConflictReport]:
        """Pairwise scan a list of memories; return all detected conflicts."""
        reports: List[ConflictReport] = []
        n = len(memories)
        for i in range(n):
            for j in range(i + 1, n):
                r = self.check_pair(memories[i], memories[j], index_a=i, index_b=j)
                if r is not None:
                    reports.append(r)
        return reports


# Minimal English/Turkish stopword set for the Jaccard fallback. Kept
# deliberately small — we want topic overlap, not perfect IR.
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "is", "are", "was", "were",
    "be", "been", "of", "to", "in", "on", "at", "for", "with", "by",
    "this", "that", "it", "as", "from", "user", "users",
    "ve", "bir", "bu", "şu", "ile", "için", "olan", "olur",
}


__all__ = ["ConflictDetector", "ConflictReport"]
