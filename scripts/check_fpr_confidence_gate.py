#!/usr/bin/env python3
"""Statistical FPR gate on the large benign FP-stress corpus.

A measured FPR of 0.000 on 55 benign samples is meaningless — its
95 %-confidence upper bound is ~6.5 %. This gate runs the Analyzer over
the large authored benign corpus (`benign_calibration_large.json`,
~1500 realistic memory-writes weighted toward trigger-word-adjacent hard
negatives) with proper per-sample isolation (unique source_id + agent_id
so the session-buffer / cross-entry-correlation layers do not bleed
between unrelated samples), then asserts the **Wilson 95 % upper bound**
on the block rate is below a target.

With N≈1500 the Wilson bound is tight, so passing this gate is a
defensible production-precision claim — unlike the gold-only FPR.

    python scripts/check_fpr_confidence_gate.py
    python scripts/check_fpr_confidence_gate.py --max-upper 0.03
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
DEFAULT_CORPUS = ROOT / "ml" / "data" / "benign_calibration_large.json"


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    den = 1 + z * z / n
    center = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return center + half


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default=str(DEFAULT_CORPUS))
    ap.add_argument("--max-upper", type=float, default=0.03,
                    help="max allowed Wilson 95%% upper bound on benign block rate")
    ap.add_argument("--min-n", type=int, default=800,
                    help="reject corpora too small to give a meaningful bound")
    args = ap.parse_args()

    from memgar import Analyzer, MemoryEntry, Decision

    samples = json.loads(Path(args.corpus).read_text(encoding="utf-8"))["samples"]
    benign = [s for s in samples if s.get("label", 0) == 0]
    n = len(benign)
    if n < args.min_n:
        print(f"ERROR: benign corpus too small ({n} < {args.min_n}); "
              "bound would be meaningless.")
        return 1

    a = Analyzer(use_llm=False)
    blocked = []
    for i, s in enumerate(benign):
        r = a.analyze(MemoryEntry(content=s["text"], source_type="memory",
                                  source_id=f"fpr-{i}",
                                  metadata={"agent_id": f"fpr-{i}"}))
        if r.decision == Decision.BLOCK:
            blocked.append(s["text"])

    k = len(blocked)
    fpr = k / n
    upper = wilson_upper(k, n)
    print()
    print(f"Benign samples (isolated)     : {n}")
    print(f"Blocked (false positives)     : {k}")
    print(f"Point FPR                     : {fpr:.4f}")
    print(f"Wilson 95% upper bound        : {upper:.4f}  ({upper*100:.2f}%)")
    print(f"Gate threshold (max upper)    : {args.max_upper:.4f}  ({args.max_upper*100:.2f}%)")
    print()
    if blocked[:8]:
        print("Sample false positives:")
        for t in blocked[:8]:
            print(f"  - {t[:88]}")
        print()

    if upper > args.max_upper:
        print(f"GATE FAILED: Wilson upper bound {upper:.4f} > {args.max_upper:.4f}")
        print("Fix: tighten the over-broad pattern(s) firing on the listed benigns,")
        print("then re-run. Do not lower the threshold without documenting why.")
        return 1
    print("FPR confidence gate PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
