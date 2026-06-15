#!/usr/bin/env python3
"""Mine false negatives — every attack the default Analyzer fails to block.

Phase 0 of the recall-improvement program. Runs the default
``Analyzer(use_llm=False)`` over every available attack corpus and records
each MISS (a label=1 attack that did not get BLOCK/QUARANTINE) with enough
metadata to drive targeted pattern / similarity-corpus expansion in Phase 1.

Corpora are split into two relevance tiers because they carry different
threat models:

  PRIMARY  — memory poisoning (memgar's OWASP ASI06 mission):
             memgar_threat_model.jsonl + calibration_corpus label=1 attacks.
             Misses here are the priority — they are in-scope by definition.

  ADJACENT — jailbreak / harmful-content corpora (AdvBench, JailbreakBench,
             HarmBench). Different threat model; misses are only worth fixing
             where the attack is also a memory-write/persistence vector.
             Reported for transparency, tagged ``adjacent``.

Output:
  - benchmarks/false_negatives.json   every miss + text + risk + layers_used
  - stdout summary                    per-corpus recall + miss counts

Usage:
  python scripts/mine_false_negatives.py
  python scripts/mine_false_negatives.py --limit 100   # quick smoke
  python scripts/mine_false_negatives.py --output benchmarks/fn.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
CORPUS_DIR = ROOT / "ml" / "data" / "_corpus_cache"

from memgar import Analyzer, Decision, MemoryEntry  # noqa: E402


# --- corpus loaders --------------------------------------------------------

def _csv_col(path: Path, col: str, limit: Optional[int]) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            v = (row.get(col) or "").strip()
            if v:
                out.append(v)
            if limit and len(out) >= limit:
                break
    return out


def _jsonl_label(path: Path, label: int, limit: Optional[int]) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("label") != label:
                continue
            t = (row.get("text") or "").strip()
            if t:
                out.append(t)
            if limit and len(out) >= limit:
                break
    return out


def _json_label(path: Path, label: int, limit: Optional[int]) -> List[str]:
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    items = data if isinstance(data, list) else data.get("samples", data.get("entries", []))
    out = [(x.get("text") or "").strip() for x in items
           if isinstance(x, dict) and x.get("label") == label]
    out = [t for t in out if t]
    return out[:limit] if limit else out


def load_attack_corpora(limit: Optional[int]) -> List[Dict[str, Any]]:
    """Return [{name, tier, samples}] for every attack corpus available."""
    corpora = [
        # PRIMARY — memory poisoning (in-scope)
        ("memgar_threat_model", "primary",
         _jsonl_label(CORPUS_DIR / "memgar_threat_model.jsonl", 1, limit)),
        ("calibration_gold", "primary",
         _json_label(ROOT / "ml" / "data" / "calibration_corpus.json", 1, limit)),
        ("gandalf", "primary",
         _jsonl_label(CORPUS_DIR / "gandalf.jsonl", 1, limit)),
        # ADJACENT — jailbreak / harmful (different threat model)
        ("advbench", "adjacent", _csv_col(CORPUS_DIR / "advbench.csv", "goal", limit)),
        ("jbb_harmful", "adjacent", _csv_col(CORPUS_DIR / "jbb_harmful.csv", "Goal", limit)),
        ("harmbench", "adjacent", _csv_col(CORPUS_DIR / "harmbench.csv", "Behavior", limit)),
        ("trustairlab_jb", "adjacent",
         _jsonl_label(CORPUS_DIR / "trustairlab_jb.jsonl", 1, limit)),
    ]
    return [{"name": n, "tier": t, "samples": s} for n, t, s in corpora if s]


# --- evaluation ------------------------------------------------------------

def _blocked(result: Any) -> bool:
    return result.decision in (Decision.BLOCK, Decision.QUARANTINE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=None,
                    help="cap samples per corpus (smoke runs)")
    ap.add_argument("--output", default="benchmarks/false_negatives.json")
    args = ap.parse_args()

    analyzer = Analyzer(use_llm=False)
    corpora = load_attack_corpora(args.limit)
    if not corpora:
        print("No attack corpora found in", CORPUS_DIR, file=sys.stderr)
        return 1

    all_misses: List[Dict[str, Any]] = []
    summary: List[Dict[str, Any]] = []

    for corpus in corpora:
        name, tier, samples = corpus["name"], corpus["tier"], corpus["samples"]
        caught = 0
        misses: List[Dict[str, Any]] = []
        t0 = time.perf_counter()
        for idx, text in enumerate(samples):
            r = analyzer.analyze(MemoryEntry(
                content=text, source_type="external", source_id=f"{name}/{idx}"))
            if _blocked(r):
                caught += 1
            else:
                misses.append({
                    "corpus": name,
                    "tier": tier,
                    "text": text[:500],
                    "risk_score": r.risk_score,
                    "decision": r.decision.value,
                    "layers_used": r.layers_used or [],
                    "near_miss": r.risk_score >= 10,  # fired something but under threshold
                })
        dt = time.perf_counter() - t0
        n = len(samples)
        recall = caught / n if n else 0.0
        summary.append({
            "corpus": name, "tier": tier, "n": n,
            "caught": caught, "missed": n - caught,
            "recall": round(recall, 4),
            "near_misses": sum(1 for m in misses if m["near_miss"]),
            "sec": round(dt, 1),
        })
        all_misses.extend(misses)
        print(f"  [{tier:8s}] {name:22s} recall={recall:5.1%} "
              f"({caught}/{n})  misses={n-caught}  near={summary[-1]['near_misses']}",
              file=sys.stderr, flush=True)

    out = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "analyzer_config": "Analyzer(use_llm=False)",
        "limit": args.limit,
        "summary": summary,
        "false_negatives": all_misses,
    }
    out_path = ROOT / args.output
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2))

    # console rollup
    prim = [s for s in summary if s["tier"] == "primary"]
    adj = [s for s in summary if s["tier"] == "adjacent"]
    prim_n = sum(s["n"] for s in prim)
    prim_caught = sum(s["caught"] for s in prim)
    adj_n = sum(s["n"] for s in adj)
    adj_caught = sum(s["caught"] for s in adj)
    print("\n" + "=" * 64)
    print("FALSE-NEGATIVE MINE — default Analyzer(use_llm=False)")
    print("=" * 64)
    if prim_n:
        print(f"PRIMARY  (memory poisoning): {prim_caught}/{prim_n} = "
              f"{prim_caught/prim_n:.1%} recall  |  {prim_n-prim_caught} misses")
    if adj_n:
        print(f"ADJACENT (jailbreak/harmful): {adj_caught}/{adj_n} = "
              f"{adj_caught/adj_n:.1%} recall  |  {adj_n-adj_caught} misses")
    near = sum(1 for m in all_misses if m["near_miss"])
    print(f"\nTotal misses: {len(all_misses)}  ({near} near-misses scored >=10 "
          f"— these are the cheapest to recover)")
    print(f"Dumped → {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
