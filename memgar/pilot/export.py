"""Convert pilot JSONL into a training corpus.

The collected stream stores Memgar's verdict per write; we use it as a *weak
label* for training:

  decision=ALLOW       -> label 0 (benign)
  decision=BLOCK       -> label 1 (attack)
  decision=QUARANTINE  -> routed to a review queue, not training (by default)

The output schema matches the rest of the repo's corpora so it slots straight
into ``scripts/prepare_v2_dataset.py``::

    {"text": "...", "label": 0|1, "source": "pilot",
     "agent_id": "<HASH:...>", "threats": [...], "redactions": {...}}

Usage::

    python -m memgar.pilot.export \\
        --input  ml/pilot_data \\
        --output ml/data/pilot_corpus.json \\
        --review-queue ml/data/pilot_review_queue.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

DECISION_TO_LABEL: Dict[str, int] = {
    "allow": 0,
    "block": 1,
}


def iter_rows(input_dir: Path) -> Iterable[Dict[str, Any]]:
    if input_dir.is_file():
        files = [input_dir]
    else:
        files = sorted(input_dir.glob("pilot_*.jsonl"))
    for path in files:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def to_corpus(
    rows: Iterable[Dict[str, Any]],
    min_length: int = 8,
    max_length: int = 2000,
    dedup: bool = True,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Counter]:
    train: List[Dict[str, Any]] = []
    review: List[Dict[str, Any]] = []
    seen: set[str] = set()
    stats: Counter = Counter()
    for row in rows:
        text = (row.get("text") or "").strip()
        if not (min_length <= len(text) <= max_length):
            stats["filtered_length"] += 1
            continue
        if dedup:
            if text in seen:
                stats["filtered_dup"] += 1
                continue
            seen.add(text)
        decision = (row.get("decision") or "").lower()
        if decision == "quarantine":
            review.append({
                "text": text,
                "source": "pilot",
                "agent_id": row.get("agent_id"),
                "threats": row.get("threats", []),
                "risk_score": row.get("risk_score"),
                "redactions": row.get("redactions", {}),
                "note": "quarantine — needs human review before training",
            })
            stats["review"] += 1
            continue
        label = DECISION_TO_LABEL.get(decision)
        if label is None:
            stats["unknown_decision"] += 1
            continue
        train.append({
            "text": text,
            "label": label,
            "source": "pilot",
            "agent_id": row.get("agent_id"),
            "threats": row.get("threats", []),
            "redactions": row.get("redactions", {}),
        })
        stats[f"label_{label}"] += 1
    return train, review, stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default="ml/pilot_data",
                    help="directory of pilot_*.jsonl files (or a single file)")
    ap.add_argument("--output", default="ml/data/pilot_corpus.json")
    ap.add_argument("--review-queue", default="ml/data/pilot_review_queue.json")
    ap.add_argument("--min-length", type=int, default=8)
    ap.add_argument("--max-length", type=int, default=2000)
    ap.add_argument("--no-dedup", action="store_true")
    args = ap.parse_args()

    train, review, stats = to_corpus(
        iter_rows(Path(args.input)),
        min_length=args.min_length,
        max_length=args.max_length,
        dedup=not args.no_dedup,
    )
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(
        json.dumps({"version": 1, "source": "pilot",
                    "n": len(train), "samples": train},
                   ensure_ascii=False, indent=2),
        encoding="utf-8")
    Path(args.review_queue).parent.mkdir(parents=True, exist_ok=True)
    Path(args.review_queue).write_text(
        json.dumps({"version": 1, "n": len(review), "samples": review},
                   ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"corpus      : {len(train)} rows  ({dict(stats)})  -> {args.output}")
    print(f"review queue: {len(review)} rows -> {args.review_queue}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
