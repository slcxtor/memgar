#!/usr/bin/env python3
"""
Generalization gate — does detection survive prose the patterns never saw?

Every other gate in this repo scores memgar against corpora the pattern
library was authored against: the gold corpus, the mined subset, the
augmented wrappers. Those measure corpus fit. They cannot tell you whether
a fresh attack, written in words nobody enumerated, gets caught — and that
is the only question that matters for a memory-poisoning defence, because
a planted memory has to read like a legitimate memory to survive.

This gate runs `ml/data/generalization_corpus.json`: held-out novel prose,
every attack paired with a benign built on the same sentence frame. The
pairing is the point. A detector keying on surface structure rather than
intent cannot score well on one half without wrecking the other.

Two rules make the number honest:

1. **A fresh Analyzer per sample.** The correlation detector raises scores
   from entries seen earlier in the same process. Feeding a corpus through
   one Analyzer inflates recall and FPR together and flatters the result —
   measured at 5/10 shared versus 1/10 isolated on an early draft of this
   corpus. Single memory writes are the realistic case, so isolate.

2. **Regression-only, not a bar to clear.** Absolute recall starts low. A
   gate that always fails gets disabled, and a disabled gate measures
   nothing. So this one prints the absolute numbers loudly and fails only
   when they get *worse* than the recorded baseline.

Usage:
    python scripts/check_generalization_gate.py
    python scripts/check_generalization_gate.py --update-baseline
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("MEMGAR_FEED_ENABLED", "false")
os.environ.setdefault("MEMGAR_OBSERVABILITY_ENABLED", "false")

CORPUS = REPO_ROOT / "ml" / "data" / "generalization_corpus.json"
BASELINE = REPO_ROOT / "ml" / "artifacts" / "generalization_baseline.json"

# Slack is counted in samples, not percentage points. A fractional tolerance
# is vacuous at a low baseline: 0.05 against a recall of 0.026 puts the floor
# below zero, so detection could collapse to nothing and still "pass".
SLACK_SAMPLES = 2

# Whatever the slack, a baseline that caught something may not fall to
# catching nothing. Losing every detection you had is a regression at any
# scale, and this is the case that matters most while recall is low.
def bounds(baseline: dict, n_attack: int, n_benign: int) -> tuple[float, float]:
    """Recall floor and FPR ceiling, derived in whole samples."""
    caught = round(baseline["recall"] * n_attack)
    floor = max(caught - SLACK_SAMPLES, 0) / n_attack if n_attack else 0.0
    if caught >= 1:
        floor = max(floor, 1 / n_attack)
    flagged = round(baseline["fpr"] * n_benign)
    ceiling = (flagged + SLACK_SAMPLES) / n_benign if n_benign else 1.0
    return round(floor, 4), round(ceiling, 4)


def evaluate(samples: list[dict]) -> dict:
    """Score each sample with its own Analyzer (see rule 1 in the docstring)."""
    from memgar.analyzer import Analyzer
    from memgar.models import MemoryEntry

    per_category: dict[str, dict[str, int]] = defaultdict(lambda: {"n": 0, "hit": 0})
    caught = missed = flagged = clean = 0
    misses: list[str] = []
    false_positives: list[str] = []

    for sample in samples:
        analyzer = Analyzer(use_llm=False)
        result = analyzer.analyze(
            MemoryEntry(
                content=sample["text"],
                source_type="document",
                source_id="untrusted-generalization-probe",
            )
        )
        acted_on = result.decision.value != "allow"
        category = sample["category"]
        per_category[category]["n"] += 1

        if sample["label"] == 1:
            if acted_on:
                caught += 1
                per_category[category]["hit"] += 1
            else:
                missed += 1
                misses.append(sample["text"])
        else:
            if acted_on:
                flagged += 1
                false_positives.append(sample["text"])
            else:
                clean += 1
                per_category[category]["hit"] += 1

    n_attack = caught + missed
    n_benign = flagged + clean
    return {
        "n_attack": n_attack,
        "n_benign": n_benign,
        "recall": round(caught / n_attack, 4) if n_attack else 0.0,
        "fpr": round(flagged / n_benign, 4) if n_benign else 0.0,
        "per_category_recall": {
            c: round(v["hit"] / v["n"], 4)
            for c, v in sorted(per_category.items())
            if not c.endswith("_benign_pair")
        },
        "misses": misses,
        "false_positives": false_positives,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", default=str(CORPUS))
    parser.add_argument("--baseline", default=str(BASELINE))
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Record the current numbers as the new floor.",
    )
    parser.add_argument("--verbose", action="store_true", help="List every miss and FP.")
    args = parser.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    metrics = evaluate(corpus["samples"])

    print()
    print("Generalization gate — held-out novel prose")
    print("=" * 78)
    print(f"  attack recall           {metrics['recall']:.3f}  "
          f"({metrics['n_attack']} samples)")
    print(f"  benign FPR              {metrics['fpr']:.3f}  "
          f"({metrics['n_benign']} structurally matched)")
    print()
    print("  per-category recall")
    for category, value in metrics["per_category_recall"].items():
        print(f"    {category:32} {value:.3f}")

    if args.verbose:
        if metrics["misses"]:
            print("\n  missed attacks:")
            for text in metrics["misses"]:
                print(f"    - {text[:92]}")
        if metrics["false_positives"]:
            print("\n  false positives:")
            for text in metrics["false_positives"]:
                print(f"    - {text[:92]}")

    baseline_path = Path(args.baseline)
    if args.update_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(
                {
                    "corpus": Path(args.corpus).name,
                    "n_attack": metrics["n_attack"],
                    "n_benign": metrics["n_benign"],
                    "recall": metrics["recall"],
                    "fpr": metrics["fpr"],
                    "per_category_recall": metrics["per_category_recall"],
                    "slack_samples": SLACK_SAMPLES,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"\nBaseline recorded → {baseline_path}")
        return 0

    if not baseline_path.exists():
        print(f"\nNo baseline at {baseline_path}.")
        print("Record one with: python scripts/check_generalization_gate.py --update-baseline")
        return 1

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    recall_floor, fpr_ceiling = bounds(
        baseline, metrics["n_attack"], metrics["n_benign"]
    )

    print()
    print(f"{'Metric':<28}{'Actual':>10}{'Baseline':>11}{'Bound':>10}  Status")
    print("-" * 78)
    failures = []

    ok = metrics["recall"] >= recall_floor
    failures += [] if ok else ["recall"]
    print(f"{'Novel-prose attack recall':<28}{metrics['recall']:>10.3f}"
          f"{baseline['recall']:>11.3f}{recall_floor:>10.3f}  "
          f"{'PASS' if ok else 'FAIL'}")

    ok = metrics["fpr"] <= fpr_ceiling
    failures += [] if ok else ["fpr"]
    print(f"{'Matched-benign FPR':<28}{metrics['fpr']:>10.3f}"
          f"{baseline['fpr']:>11.3f}{fpr_ceiling:>10.3f}  "
          f"{'PASS' if ok else 'FAIL'}")

    print()
    if failures:
        print(f"REGRESSION in: {', '.join(failures)}")
        print("Detection on unseen prose got worse. Fix it, or justify and re-record")
        print("the baseline with --update-baseline.")
        return 1

    improved = (
        metrics["recall"] > baseline["recall"] + 1e-9
        or metrics["fpr"] < baseline["fpr"] - 1e-9
    )
    print("No regression.")
    if improved:
        print("Numbers improved — re-record the floor with --update-baseline.")
    print()
    print("Reminder: this corpus is a thermometer, not a target. Patterns written")
    print("to match these samples make the gate stop measuring what it exists for.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
