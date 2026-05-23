#!/usr/bin/env python3
"""Import realistic *benign* corpora and filter them down to memgar's
memory-write surface.

Why this script exists
----------------------
The attack side of memgar's corpus is in good shape — AdvBench / JBB /
HarmBench / Gandalf / deepset / TrustAIRLab / WildJailbreak cover real
in-the-wild jailbreaks. The weakness is the **benign** side: most of our
negatives come from synthetic templates that don't look like prosaic
user-facing agent traffic, which inflates production FPR (see CLAUDE.md).

This script pulls from real-conversation datasets and keeps only the
turns that look like things an agent might *legitimately* store in
memory — user preferences, persona notes, recall-style instructions,
short factual reminders. Everything else (multi-paragraph reasoning,
chain-of-thought, code dumps, RLHF-style refusals) is dropped because
it doesn't match the memory-write distribution memgar protects.

Sources (license-clean only — Apache 2.0 / MIT / CC-BY-SA / CC-BY-4.0)
---------------------------------------------------------------------
  oasst      OpenAssistant/oasst1                          Apache-2.0
  hh_rlhf   Anthropic/hh-rlhf  (helpful-base only)         MIT
  dolly     databricks/databricks-dolly-15k                CC-BY-SA-3.0
  lmsys     lmsys/lmsys-chat-1m   (gated, needs HF_TOKEN)  CC-BY-4.0

Alpaca and ShareGPT are *deliberately excluded* — Alpaca is CC-BY-NC
(no commercial use), ShareGPT's provenance is ambiguous.

Usage
-----
    python scripts/import_benign_corpora.py
        [--sources oasst,hh_rlhf,dolly,lmsys]
        [--out ml/data/benign_corpora.json]
        [--cache-dir ml/data/_corpus_cache]
        [--max-per-source 0]
        [--min-length 10] [--max-length 500]
        [--seed 42]

Output
------
    ml/data/benign_corpora.json  — list of memory-write-shaped benigns,
                                    same schema as external_corpus_*.
    ml/data/CORPUS_LICENSES.md   — license/attribution appended.

The output is consumed by prepare_v2_dataset.py via --include-benign-corpora.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Reuse the HF/network plumbing from the attack importer so we don't
# duplicate retry/backoff/caching logic.
from scripts.import_public_corpora import (  # noqa: E402
    _content_hash,
    _detect_language,
    _fetch_hf_dataset,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("import_benign")


# ---------------------------------------------------------------------------
# Memory-write filtering — the heart of this script
# ---------------------------------------------------------------------------
#
# We want utterances that look like "things an agent legitimately stores in
# long-term memory". That's a narrow slice of any conversation corpus:
# preferences, facts about the user, persona notes, recall instructions,
# short factual reminders. NOT chain-of-thought reasoning, NOT code blocks,
# NOT RLHF refusals, NOT multi-paragraph essays.
#
# Strategy: two-stage filter.
#   (1) Lexical pre-filter — cheap, catches obvious matches/misses.
#   (2) Structural filter — length, sentence count, code/markup density.
# Both must pass.

# Phrases that strongly indicate the speaker is asking the agent to remember
# / store / recall something. Order doesn't matter; presence of any token
# in the lemma class is sufficient.
_MEMORY_WRITE_MARKERS = (
    # English — direct memory operations
    r"\bremember\b", r"\bsave (this|that|the)\b", r"\bstore (this|that)\b",
    r"\bnote that\b", r"\bplease note\b", r"\bkeep in mind\b",
    r"\bdon'?t forget\b", r"\bfor (future|next) (time|reference)\b",

    # Preferences
    r"\b(i|my) prefer\w*\b", r"\bi (like|love|enjoy|hate|dislike)\b",
    r"\bmy favorite\b", r"\bmy preference\b", r"\bmy name is\b",
    r"\bmy (email|phone|address|birthday|timezone)\b",

    # Recall-style instructions
    r"\bfrom now on\b", r"\balways\b", r"\bnever\b",
    r"\bwhen(ever)? i ask\b", r"\bif i (say|ask|tell)\b",

    # Persona / settings (legitimate)
    r"\b(use|respond in|reply in|answer in) (english|turkish|spanish|french|german|chinese|japanese|portuguese|italian|russian)\b",
    r"\b(formal|informal|casual|concise|detailed|brief|short|long) (tone|style|response|answer)\b",

    # Factual reminders
    r"\bimportant:",                   # ':' is non-word, drop trailing \b
    r"\bkey (info|point|fact)\b",
    r"\bfyi\b", r"\bjust so you know\b",

    # User-attribute statements ("I am", "I'm", "I work as", "I live in")
    r"\bi['\s]?(am|'?m)\b",
    r"\bi work as\b", r"\bi live in\b",
)
_MEMORY_WRITE_RE = re.compile("|".join(_MEMORY_WRITE_MARKERS), re.IGNORECASE)

# Strong negative signals — if any match, drop the row even if a positive
# marker also matched. Mostly: chain-of-thought, code, refusals, RLHF-isms.
_REJECT_MARKERS = (
    r"```",                             # code blocks
    r"\b(def |function |class |import |return |const |let |var )\w+",  # code keywords
    r"<\w+[^>]*>.*</\w+>",              # HTML/XML
    r"step \d+:",                       # CoT step lists
    r"^(sure|certainly|of course|absolutely|happy to)[,!]",  # RLHF intros
    r"i (cannot|can'?t|won'?t|will not) (help|assist|do|provide|generate)",  # refusals
    r"\bas an? (ai|language model|assistant)\b",  # RLHF self-references
    r"\b(it'?s important to|note that|please be aware) (note|remember|keep|consider)",  # over-meta phrasing
)
_REJECT_RE = re.compile("|".join(_REJECT_MARKERS), re.IGNORECASE | re.MULTILINE)


# Toxicity / profanity filter. We're not doing full content moderation —
# memgar isn't trying to be a profanity filter — but we drop rows that
# are clearly slurs / hateful / sexual so the benign label stays clean.
# This is a small, conservative list; for real moderation use a proper
# classifier upstream.
_TOXIC_TERMS = (
    "fuck", "shit", "bitch", "asshole", "cunt", "dick", "pussy",
    "nigger", "faggot", "retard", "kike", "spic", "chink",
    "rape", "kill yourself", "kys",
)
_TOXIC_RE = re.compile(r"\b(" + "|".join(_TOXIC_TERMS) + r")\b", re.IGNORECASE)


def _is_memory_write(text: str, *, min_len: int = 10, max_len: int = 500) -> bool:
    """Return True if `text` looks like a legitimate memory-write utterance.

    Filter is conservative on purpose — we'd rather drop 90% of a corpus
    and keep clean signal than keep 50% with noise. The downstream
    transformer doesn't care about quantity past a few thousand benigns.
    """
    if not text:
        return False
    t = text.strip()
    n = len(t)
    if n < min_len or n > max_len:
        return False
    # Drop multi-paragraph blocks — memory writes are 1-2 sentences.
    if t.count("\n\n") >= 1:
        return False
    if t.count(". ") + t.count("! ") + t.count("? ") > 3:
        return False
    # Reject if any negative marker fires.
    if _REJECT_RE.search(t):
        return False
    # Reject toxic content (keeps benign label clean).
    if _TOXIC_RE.search(t):
        return False
    # Require at least one positive memory-write marker.
    if not _MEMORY_WRITE_RE.search(t):
        return False
    # Reject non-English (memgar's en focus — Turkish gets its own pipeline).
    if _detect_language(t) != "en":
        return False
    return True


# ---------------------------------------------------------------------------
# Source parsers
# ---------------------------------------------------------------------------

def _iter_jsonl_blob(blob: bytes) -> Iterator[dict]:
    for line in blob.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def _parse_oasst(blob: bytes) -> Iterable[dict]:
    """OpenAssistant oasst1 — conversation tree. Pull `role=prompter` turns
    (user-side utterances) because those are what an agent would memorise."""
    for row in _iter_jsonl_blob(blob):
        if row.get("role") != "prompter":
            continue
        text = (row.get("text") or "").strip()
        if not text:
            continue
        yield {
            "text": text,
            "label": 0,
            "category": "benign_memory_write",
            "source": "openassistant_oasst1",
            "_orig_id": row.get("message_id", "")[:32],
        }


def _parse_hh_rlhf(blob: bytes) -> Iterable[dict]:
    """Anthropic HH-RLHF helpful subset — extract the human's first turn
    (the request / preference statement), drop the assistant chain.
    The dataset stores conversations as 'chosen' / 'rejected' strings with
    'Human:' / 'Assistant:' separators."""
    for row in _iter_jsonl_blob(blob):
        chosen = row.get("chosen") or ""
        if not chosen:
            continue
        # First Human turn only — that's the user-side memory-write candidate.
        parts = chosen.split("\n\nAssistant:", 1)
        human = parts[0].replace("\n\nHuman:", "").strip()
        if not human:
            continue
        yield {
            "text": human,
            "label": 0,
            "category": "benign_memory_write",
            "source": "hh_rlhf_helpful",
        }


def _parse_dolly(blob: bytes) -> Iterable[dict]:
    """databricks-dolly-15k — instruction field is the user-side utterance."""
    for row in _iter_jsonl_blob(blob):
        instruction = (row.get("instruction") or "").strip()
        if not instruction:
            continue
        yield {
            "text": instruction,
            "label": 0,
            "category": "benign_memory_write",
            "source": "dolly_15k",
            "_orig_id": row.get("category", "")[:32],
        }


def _parse_lmsys(blob: bytes) -> Iterable[dict]:
    """LMSYS Chat-1M — extract user turns from the conversation field.
    Conversations are stored as a list of {role, content} dicts."""
    for row in _iter_jsonl_blob(blob):
        conv = row.get("conversation") or []
        if not isinstance(conv, list):
            continue
        for turn in conv:
            if turn.get("role") != "user":
                continue
            content = (turn.get("content") or "").strip()
            if not content:
                continue
            yield {
                "text": content,
                "label": 0,
                "category": "benign_memory_write",
                "source": "lmsys_chat_1m",
            }
            # One user-turn per conversation is plenty — LMSYS is 1M rows,
            # taking every turn would dominate the corpus.
            break


# ---------------------------------------------------------------------------
# Source registry
# ---------------------------------------------------------------------------

@dataclass
class BenignSource:
    name: str
    hf_dataset: str
    license_name: str
    license_url: str
    attribution: str
    notes: str
    parser: Callable[[bytes], Iterable[dict]] = field(repr=False)
    splits: tuple[str, ...] = ("train",)
    config: str = "default"
    gated: bool = False
    default_cap: int = 0       # 0 = no cap, pulled until exhaustion or filter saturation


SOURCES: dict[str, BenignSource] = {
    "oasst": BenignSource(
        name="OpenAssistant oasst1",
        hf_dataset="OpenAssistant/oasst1",
        license_name="Apache-2.0",
        license_url="https://huggingface.co/datasets/OpenAssistant/oasst1",
        attribution="Köpf et al., 'OpenAssistant Conversations — Democratizing Large Language Model Alignment', NeurIPS 2023 (LAION-AI)",
        notes="Real user-side prompts from the OpenAssistant project. Pulled `role=prompter` turns only; memory-write filter applied.",
        parser=_parse_oasst,
        splits=("train", "validation"),
        default_cap=40000,
    ),
    "hh_rlhf": BenignSource(
        name="Anthropic HH-RLHF (helpful-base)",
        hf_dataset="Anthropic/hh-rlhf",
        license_name="MIT",
        license_url="https://huggingface.co/datasets/Anthropic/hh-rlhf",
        attribution="Bai et al., 'Training a Helpful and Harmless Assistant with Reinforcement Learning from Human Feedback', Anthropic, 2022",
        notes="Helpful-base subset only (we use the human's first turn — preference / request statement). Harmless-base is *not* used here, it lives on the attack side of the corpus.",
        parser=_parse_hh_rlhf,
        config="helpful-base",
        splits=("train",),
        default_cap=20000,
    ),
    "dolly": BenignSource(
        name="Databricks Dolly 15K",
        hf_dataset="databricks/databricks-dolly-15k",
        license_name="CC-BY-SA-3.0",
        license_url="https://huggingface.co/datasets/databricks/databricks-dolly-15k",
        attribution="Conover et al., 'Free Dolly: Introducing the World's First Truly Open Instruction-Tuned LLM', Databricks, 2023",
        notes="Manually authored instruction-following pairs across 7 task categories. We keep the `instruction` field.",
        parser=_parse_dolly,
        splits=("train",),
        default_cap=15000,
    ),
    "lmsys": BenignSource(
        name="LMSYS Chat-1M",
        hf_dataset="lmsys/lmsys-chat-1m",
        license_name="LMSYS-Chat-1M License (research-only)",
        license_url="https://huggingface.co/datasets/lmsys/lmsys-chat-1m",
        attribution="Zheng et al., 'LMSYS-Chat-1M: A Large-Scale Real-World LLM Conversation Dataset', ICLR 2024",
        notes="GATED — requires HF_TOKEN and accepted dataset terms. First user turn per conversation only; memory-write filter applied to keep the slice tight (~1-5%% of source rows survive).",
        parser=_parse_lmsys,
        splits=("train",),
        default_cap=80000,    # we'll fetch this many raw rows; filter keeps ~1-5%
        gated=True,
    ),
}


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _load_source(src: BenignSource, cache_dir: Path, max_rows: int,
                 hf_token: str | None) -> list[dict]:
    """Pull a source and return the *unfiltered* row list."""
    if src.gated and not hf_token:
        logger.warning("%s is gated and HF_TOKEN is not set — skipping.", src.name)
        return []
    cache_path = cache_dir / f"benign_{src.hf_dataset.replace('/', '__')}__{src.config}.jsonl"
    row_cap = max_rows or src.default_cap
    logger.info("fetching %s (cap=%d) …", src.name, row_cap)
    try:
        blob = _fetch_hf_dataset(
            dataset=src.hf_dataset,
            splits=src.splits,
            config=src.config,
            cache_path=cache_path,
            hf_token=hf_token,
            row_cap=row_cap,
        )
    except Exception as e:
        logger.error("failed to fetch %s: %s", src.name, e)
        return []
    rows = list(src.parser(blob))
    logger.info("  → %d raw rows from %s", len(rows), src.name)
    return rows


def _filter_and_dedup(rows: list[dict], min_len: int, max_len: int,
                      seen_hashes: set[str]) -> list[dict]:
    """Apply memory-write filter + content-hash dedup. `seen_hashes` is
    mutated in place so the caller can dedup across sources."""
    out: list[dict] = []
    for r in rows:
        t = (r.get("text") or "").strip()
        if not _is_memory_write(t, min_len=min_len, max_len=max_len):
            continue
        h = _content_hash(t)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        r["text"] = t
        r["_content_hash"] = h
        out.append(r)
    return out


def _write_license_block(out_md: Path, used: list[BenignSource]) -> None:
    """Append a benign-corpora license block to CORPUS_LICENSES.md if any
    benign source produced rows. Idempotent — re-running overwrites the
    benign block but keeps the attack block intact."""
    if not out_md.exists():
        return  # the attack importer will create the file
    text = out_md.read_text(encoding="utf-8")
    marker = "\n## Benign corpora (memory-write surface)\n"
    end_marker = "\n## "  # next section, if any
    if marker in text:
        before, rest = text.split(marker, 1)
        # strip the existing benign block up to the next "## " heading
        if end_marker in rest[1:]:
            _, after = rest.split(end_marker, 1)
            text = before + end_marker + after
        else:
            text = before.rstrip() + "\n"
    block = [marker.strip()]
    for s in used:
        block.append(f"\n### {s.name}\n")
        block.append(f"- HuggingFace: `{s.hf_dataset}`")
        block.append(f"- License: [{s.license_name}]({s.license_url})")
        block.append(f"- Attribution: {s.attribution}")
        block.append(f"- Notes: {s.notes}")
    out_md.write_text(text.rstrip() + "\n\n" + "\n".join(block) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sources", default="oasst,hh_rlhf,dolly",
                   help="Comma-separated source keys from SOURCES (omit gated 'lmsys' unless HF_TOKEN is set).")
    p.add_argument("--out", default="ml/data/benign_corpora.json",
                   help="Output JSON path (relative to repo root).")
    p.add_argument("--cache-dir", default="ml/data/_corpus_cache",
                   help="HuggingFace fetch cache directory.")
    p.add_argument("--license-out", default="ml/data/CORPUS_LICENSES.md",
                   help="License manifest to append benign-corpora block to.")
    p.add_argument("--max-per-source", type=int, default=0,
                   help="Override per-source row cap (0 = use source default).")
    p.add_argument("--min-length", type=int, default=10)
    p.add_argument("--max-length", type=int, default=500)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--sample-cap", type=int, default=0,
                   help="Optional cap on FINAL output size (0 = keep all filtered rows).")
    args = p.parse_args(argv)

    cache_dir = REPO_ROOT / args.cache_dir
    cache_dir.mkdir(parents=True, exist_ok=True)
    out_path = REPO_ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    license_path = REPO_ROOT / args.license_out
    hf_token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")

    requested = [s.strip() for s in args.sources.split(",") if s.strip()]
    unknown = [s for s in requested if s not in SOURCES]
    if unknown:
        logger.error("Unknown source keys: %s. Valid: %s", unknown, sorted(SOURCES))
        return 2

    rng = random.Random(args.seed)
    all_kept: list[dict] = []
    seen_hashes: set[str] = set()
    used_sources: list[BenignSource] = []

    for key in requested:
        src = SOURCES[key]
        raw = _load_source(src, cache_dir, args.max_per_source, hf_token)
        if not raw:
            continue
        kept = _filter_and_dedup(raw, args.min_length, args.max_length, seen_hashes)
        logger.info("  → %d kept after memory-write filter (%.1f%%)",
                    len(kept), 100.0 * len(kept) / max(1, len(raw)))
        all_kept.extend(kept)
        used_sources.append(src)

    rng.shuffle(all_kept)
    if args.sample_cap and len(all_kept) > args.sample_cap:
        logger.info("trimming %d → %d (--sample-cap)", len(all_kept), args.sample_cap)
        all_kept = all_kept[:args.sample_cap]

    out_path.write_text(json.dumps(all_kept, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("wrote %d benign memory-write rows → %s", len(all_kept), out_path)

    per_source = {}
    for r in all_kept:
        per_source[r["source"]] = per_source.get(r["source"], 0) + 1
    for src_key, n in sorted(per_source.items(), key=lambda kv: -kv[1]):
        logger.info("  %s: %d", src_key, n)

    _write_license_block(license_path, used_sources)
    logger.info("license manifest updated → %s", license_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
