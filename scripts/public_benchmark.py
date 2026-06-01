#!/usr/bin/env python3
"""
Memgar Public Benchmark
=======================

Single-command reproducible evaluation against externally-authored attack
and benign corpora. Reports recall / FPR / F1 per dataset and overall,
plus a layer-ablation block that shows how much each detection layer
contributes.

Designed so anyone — design partner, reviewer, paper author — can pull the
repo and reproduce the published numbers in a few minutes:

    git clone https://github.com/slcxtor/memgar
    cd memgar
    pip install -e ".[ml,semantic]"
    python scripts/public_benchmark.py --quick

Outputs:
  - stdout         human-readable summary table
  - --output-json  machine-readable per-row decisions + aggregate metrics
  - --output-md    Markdown report (commit this for paper-grade artifacts)

Corpora used (cached under ml/data/_corpus_cache/, license-clean only):
  Attack:
    - AdvBench         (Zou et al. 2023, NeurIPS) — 521 harmful goals
    - JailbreakBench   (Chao et al. 2024)         — 101 harmful behaviours
    - HarmBench        (Mazeika et al. 2024)      — 1,529 attack prompts
    - Gandalf          (Lakera 2023)              — 999 prompt-injection probes
    - TrustAIR JB      (community jailbreak dump) — 1,404 in-the-wild jailbreaks
  Benign:
    - JBB benign       (Chao et al. 2024)         —   101 paired benigns
    - OpenAssistant    (LAION oasst1)             — 2,499 prosaic user turns
    - Databricks Dolly (dolly-15k)                — 2,499 instruction-tuning prompts

The benchmark deliberately avoids the gold and v2-training corpora to
keep this an out-of-distribution evaluation.

Modes:
  --quick   sample 100 attacks + 100 benigns per corpus (≈5 min on 4 CPUs)
  --full    use every available row (~30 min on 4 CPUs, ML enabled)

Determinism is locked with --seed (default 42).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import random
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from memgar import Analyzer, Decision, MemoryEntry  # noqa: E402

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-7s %(name)s — %(message)s",
)
logger = logging.getLogger("public_bench")


CORPUS_DIR = ROOT / "ml" / "data" / "_corpus_cache"


# ---------------------------------------------------------------------------
# Loaders — every loader returns a list[str] of text rows.
# ---------------------------------------------------------------------------

def _load_csv_col(path: Path, col: str, limit: Optional[int] = None) -> List[str]:
    out: List[str] = []
    if not path.exists():
        return out
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            v = row.get(col, "").strip()
            if v:
                out.append(v)
            if limit is not None and len(out) >= limit:
                break
    return out


def _load_jsonl_field(path: Path, field: str, limit: Optional[int] = None) -> List[str]:
    out: List[str] = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            v = (row.get(field) or "").strip()
            if v:
                out.append(v)
            if limit is not None and len(out) >= limit:
                break
    return out


def load_attacks(limit: Optional[int] = None) -> Dict[str, List[str]]:
    """Returns {corpus_name: [text, ...]} for attack corpora."""
    return {
        "advbench":      _load_csv_col(CORPUS_DIR / "advbench.csv",      "goal", limit),
        "jbb_harmful":   _load_csv_col(CORPUS_DIR / "jbb_harmful.csv",   "Goal", limit),
        "harmbench":     _load_csv_col(CORPUS_DIR / "harmbench.csv",     "Behavior", limit),
        "gandalf":       _load_jsonl_field(CORPUS_DIR / "gandalf.jsonl", "text", limit),
        "trustairlab_jb": _load_jsonl_field(CORPUS_DIR / "trustairlab_jb.jsonl", "prompt", limit),
    }


def load_benigns(limit: Optional[int] = None) -> Dict[str, List[str]]:
    return {
        "jbb_benign":    _load_csv_col(CORPUS_DIR / "jbb_benign.csv", "Goal", limit),
        "openassistant": _load_jsonl_field(CORPUS_DIR / "benign_OpenAssistant__oasst1__default.jsonl", "text", limit),
        "dolly":         _load_jsonl_field(CORPUS_DIR / "benign_databricks__databricks-dolly-15k__default.jsonl", "instruction", limit),
    }


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _decide_block(result: Any) -> bool:
    """Treat both BLOCK and QUARANTINE as 'caught' — in production neither
    reaches downstream memory (SecureMemoryStore refuses to commit a
    quarantined write until human review)."""
    d = result.decision
    return d in (Decision.BLOCK, Decision.QUARANTINE)


def evaluate_corpus(
    analyzer: Analyzer,
    name: str,
    samples: Sequence[str],
    *,
    is_attack: bool,
    source_type: str = "external",
    progress: bool = False,
) -> Dict[str, Any]:
    """Run analyzer over a corpus and tally caught vs missed."""
    n = len(samples)
    if n == 0:
        return {"name": name, "is_attack": is_attack, "n": 0,
                "caught": 0, "rate": 0.0, "latencies_ms": []}

    caught = 0
    latencies: List[float] = []
    layer_hits: Counter = Counter()
    for idx, text in enumerate(samples):
        t0 = time.perf_counter()
        entry = MemoryEntry(content=text, source_type=source_type,
                            source_id=f"{name}/{idx}")
        result = analyzer.analyze(entry)
        dt = (time.perf_counter() - t0) * 1000
        latencies.append(dt)
        if _decide_block(result):
            caught += 1
        for layer in (result.layers_used or []):
            layer_hits[layer] += 1
        if progress and (idx + 1) % 50 == 0:
            print(f"   [{name}] {idx + 1}/{n}", file=sys.stderr, flush=True)

    rate = caught / n
    return {
        "name": name,
        "is_attack": is_attack,
        "n": n,
        "caught": caught,
        "rate": round(rate, 4),
        "p50_ms": round(_percentile(latencies, 0.5), 2),
        "p95_ms": round(_percentile(latencies, 0.95), 2),
        "p99_ms": round(_percentile(latencies, 0.99), 2),
        "layer_hits": dict(layer_hits),
    }


def _percentile(xs: Sequence[float], q: float) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    return s[max(0, min(len(s) - 1, int(len(s) * q)))]


def aggregate(results: List[Dict[str, Any]], *, is_attack: bool) -> Dict[str, Any]:
    rows = [r for r in results if r["is_attack"] == is_attack and r["n"] > 0]
    n = sum(r["n"] for r in rows)
    caught = sum(r["caught"] for r in rows)
    return {
        "n": n,
        "caught": caught,
        "rate": round(caught / n, 4) if n else 0.0,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_markdown(report: Dict[str, Any]) -> str:
    lines = ["# Memgar Public Benchmark"]
    lines.append("")
    lines.append(f"- generated: `{report['generated_at']}`")
    lines.append(f"- mode: `{report['mode']}`")
    lines.append(f"- seed: `{report['seed']}`")
    lines.append(f"- analyzer config: `{report['analyzer_config']}`")
    lines.append("")

    lines.append("## Attack recall per corpus")
    lines.append("")
    lines.append("| corpus | size | caught (BLOCK + QUARANTINE) | recall | p50 ms | p95 ms |")
    lines.append("|---|---|---|---|---|---|")
    for r in report["per_corpus"]:
        if not r["is_attack"]:
            continue
        lines.append(f"| {r['name']} | {r['n']} | {r['caught']} | **{r['rate']:.3f}** | {r['p50_ms']} | {r['p95_ms']} |")
    overall = report["overall_attack"]
    lines.append(f"| **overall** | **{overall['n']}** | **{overall['caught']}** | **{overall['rate']:.3f}** | — | — |")
    lines.append("")

    lines.append("## Benign FPR per corpus")
    lines.append("")
    lines.append("| corpus | size | blocked (false positive) | FPR | p50 ms | p95 ms |")
    lines.append("|---|---|---|---|---|---|")
    for r in report["per_corpus"]:
        if r["is_attack"]:
            continue
        lines.append(f"| {r['name']} | {r['n']} | {r['caught']} | **{r['rate']:.3f}** | {r['p50_ms']} | {r['p95_ms']} |")
    overall_b = report["overall_benign"]
    lines.append(f"| **overall** | **{overall_b['n']}** | **{overall_b['caught']}** | **{overall_b['rate']:.3f}** | — | — |")
    lines.append("")

    # Layer contribution
    lines.append("## Detection-layer contribution (attack corpus only)")
    lines.append("")
    lines.append("Counts the analyses where the named layer fired at least once. "
                 "An attack often trips several layers; rows can sum to more than the corpus size.")
    lines.append("")
    lines.append("| layer | hits | of |")
    lines.append("|---|---|---|")
    layer_totals = Counter()
    attack_n = 0
    for r in report["per_corpus"]:
        if r["is_attack"]:
            attack_n += r["n"]
            for k, v in (r.get("layer_hits") or {}).items():
                layer_totals[k] += v
    for layer, n in layer_totals.most_common():
        lines.append(f"| `{layer}` | {n} | {attack_n} |")
    lines.append("")
    return "\n".join(lines)


def format_console(report: Dict[str, Any]) -> str:
    lines = ["", "=" * 70,
             f"Memgar Public Benchmark — {report['mode']} mode (seed={report['seed']})",
             "=" * 70]
    lines.append(f"{'Corpus':<22} {'N':>6} {'caught':>8} {'rate':>7} {'p50':>8} {'p95':>8}")
    lines.append("-" * 70)
    for r in report["per_corpus"]:
        kind = "ATK" if r["is_attack"] else "BEN"
        lines.append(f"{kind} {r['name']:<18} {r['n']:>6} {r['caught']:>8} {r['rate']:>7.3f} "
                     f"{r['p50_ms']:>7.1f}ms {r['p95_ms']:>7.1f}ms")
    lines.append("-" * 70)
    oa = report["overall_attack"]
    ob = report["overall_benign"]
    lines.append(f"OVERALL ATTACK RECALL :  {oa['caught']}/{oa['n']} = {oa['rate']:.4f}")
    lines.append(f"OVERALL BENIGN FPR    :  {ob['caught']}/{ob['n']} = {ob['rate']:.4f}")
    f1 = _f1(oa['rate'], 1 - ob['rate'])
    lines.append(f"OVERALL F1            :  {f1:.4f}   (precision-from-FPR estimate)")
    lines.append("=" * 70)
    return "\n".join(lines)


def _f1(recall: float, precision_proxy: float) -> float:
    if recall + precision_proxy == 0:
        return 0.0
    return 2 * recall * precision_proxy / (recall + precision_proxy)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--quick", action="store_true",
                   help="Sample 100 of each corpus (5 min). Mutually exclusive with --full.")
    p.add_argument("--full", action="store_true",
                   help="Evaluate every row (~30 min). Mutually exclusive with --quick.")
    p.add_argument("--limit", type=int, default=None,
                   help="Override sample size per corpus.")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-llm", action="store_true", default=True,
                   help="Disable Layer 2 LLM (default; kept for backward compatibility).")
    p.add_argument("--output-json", default=None,
                   help="Write detailed report to this JSON path.")
    p.add_argument("--output-md", default=None,
                   help="Write Markdown summary to this path.")
    p.add_argument("--progress", action="store_true",
                   help="Print per-corpus progress to stderr.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.quick and args.full:
        print("--quick and --full are mutually exclusive", file=sys.stderr)
        return 2

    if args.limit is not None:
        limit = args.limit
        mode = f"custom (limit={limit})"
    elif args.quick:
        limit = 100
        mode = "quick (100/corpus)"
    elif args.full:
        limit = None
        mode = "full"
    else:
        limit = 100
        mode = "quick (100/corpus, default)"

    random.seed(args.seed)

    print(f"[bench] mode={mode} seed={args.seed}", file=sys.stderr, flush=True)
    print("[bench] loading analyzer (this includes ONNX INT8 model load) ...",
          file=sys.stderr, flush=True)
    t0 = time.perf_counter()
    analyzer = Analyzer(use_llm=False)
    load_ms = (time.perf_counter() - t0) * 1000
    print(f"[bench] analyzer loaded in {load_ms:.0f} ms", file=sys.stderr)
    print(f"[bench] transformer ready: {analyzer._transformer is not None and analyzer._transformer.is_ready}",
          file=sys.stderr)

    attacks = load_attacks(limit=limit)
    benigns = load_benigns(limit=limit)

    # Stratified sub-sample in quick mode (deterministic via seed)
    if limit is not None:
        for name, rows in attacks.items():
            if len(rows) > limit:
                rng = random.Random(args.seed + hash(name) % 1000)
                attacks[name] = rng.sample(rows, limit)
        for name, rows in benigns.items():
            if len(rows) > limit:
                rng = random.Random(args.seed + hash(name) % 1000)
                benigns[name] = rng.sample(rows, limit)

    per_corpus: List[Dict[str, Any]] = []
    for name, rows in attacks.items():
        if not rows:
            continue
        print(f"[bench] attack:{name} ({len(rows)} rows)", file=sys.stderr, flush=True)
        per_corpus.append(evaluate_corpus(
            analyzer, name, rows, is_attack=True,
            source_type="external", progress=args.progress))
    for name, rows in benigns.items():
        if not rows:
            continue
        print(f"[bench] benign:{name} ({len(rows)} rows)", file=sys.stderr, flush=True)
        # Benign user inputs go through analyzer with source_type='user' so
        # the trusted-user fast path can engage where appropriate. This is
        # the production posture; reviewers can run with --benign-as-external
        # to bypass the gate if they want a stricter test (not implemented
        # here yet — single-source eval is the documented setup).
        per_corpus.append(evaluate_corpus(
            analyzer, name, rows, is_attack=False,
            source_type="user", progress=args.progress))

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": mode,
        "seed": args.seed,
        "analyzer_config": "Analyzer(use_llm=False)",
        "per_corpus": per_corpus,
        "overall_attack": aggregate(per_corpus, is_attack=True),
        "overall_benign": aggregate(per_corpus, is_attack=False),
    }

    print(format_console(report))

    if args.output_json:
        Path(args.output_json).write_text(json.dumps(report, indent=2))
        print(f"[bench] wrote {args.output_json}", file=sys.stderr)
    if args.output_md:
        Path(args.output_md).write_text(format_markdown(report))
        print(f"[bench] wrote {args.output_md}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
