#!/usr/bin/env python3
"""
Continuous red-team loop — generates adversarial variants and tests them
against the LIVE Analyzer (the actual shipped detection surface: Layer 1
regex + Layer 2.5 similarity + Layer 3/4), not a disconnected training
pipeline.

Why this exists (and not `red_team_run.py` + `AutoRetrainer.retrain()`):
`retrain()` trains a standalone XGBoost model (`gradient_boost_model.pkl`)
that `memgar/analyzer.py` never loads or calls — training it, however well,
changes nothing about what `Analyzer.analyze()` actually blocks. Automating
that path would be automation theater: it runs, reports a "quality gate
passed", and the live detector is unaffected.

This script instead closes the loop that matters: generate variants of
known attacks -> run them through the real Analyzer -> anything the
Analyzer currently ALLOWs is a genuine, present-day false negative ->
dedup against what's already known -> append to the review queue for a
human/agent pass (pattern fix or corpus merge), exactly the workflow used
manually earlier in this project's history, just repeatable and automated.

Usage:
    python scripts/continuous_redteam.py --n-seeds 40 --n-variants 6
    python scripts/continuous_redteam.py --n-seeds 40 --dry-run   # report only, no file write
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("continuous_redteam")


# Subcategories present in ml/data/training_data.json that are NOT memory
# poisoning — memgar's documented scope excludes resource/cost abuse,
# supply-chain, and transport/protocol-level attacks (see CLAUDE.md: "honest
# scope discipline... out-of-scope = infra CVEs, supply-chain, hardware,
# model-training poisoning"). Seeding the red-team loop from these produces
# review-queue noise for a threat class memgar isn't meant to catch, and
# patching for them would be exactly the "content moderation" scope creep
# this project has repeatedly and deliberately declined. Kept intentionally
# short and conservative — ambiguous subcategories stay IN so a human/agent
# reviewer judges them at merge time rather than being silently dropped.
OUT_OF_SCOPE_SUBCATEGORIES = {
    "denial_of_wallet",   # resource/cost exhaustion, not memory content poisoning
    "supply_chain",       # explicitly out-of-scope per CLAUDE.md
    "websocket_attack",   # transport/protocol-level, not memory-content poisoning
}


def load_seeds(data_path: Path, n: int, seed: int, exclude_subcats: set[str]) -> list[dict]:
    import random
    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    attacks = [
        row for row in data
        if row.get("label") == 1
        and row.get("text")
        and row.get("subcategory") not in exclude_subcats
    ]
    rng = random.Random(seed)
    return rng.sample(attacks, min(n, len(attacks)))


def _tokenize(text: str) -> set[str]:
    return set(text.lower().split())


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def dedup_against(
    candidates: list[dict],
    known_texts: list[str],
    threshold: float = 0.75,
) -> list[dict]:
    """Drop candidates too similar (Jaccard on tokens) to anything already known
    (gold corpus + existing review queue), then dedup within the candidate set
    itself. Cheap, dependency-free — good enough for a coarse "is this actually
    new" filter; the existing TF-IDF cosine dedup in mine_hard_negatives.py
    handles finer curation once these graduate to that pipeline.
    """
    known_tokens = [_tokenize(t) for t in known_texts]
    kept: list[dict] = []
    kept_tokens: list[set[str]] = []
    for c in candidates:
        toks = _tokenize(c["text"])
        if any(_jaccard(toks, kt) >= threshold for kt in known_tokens):
            continue
        if any(_jaccard(toks, kt) >= threshold for kt in kept_tokens):
            continue
        kept.append(c)
        kept_tokens.append(toks)
    return kept


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n-seeds", type=int, default=40, help="Attack seeds to sample from ml/data/training_data.json")
    p.add_argument("--n-variants", type=int, default=6, help="Variants per seed (offline mutations)")
    p.add_argument("--data-path", default="ml/data/training_data.json")
    p.add_argument("--gold-path", default="ml/data/calibration_corpus.json")
    p.add_argument("--review-queue-path", default="ml/data/mined_review_queue.json")
    p.add_argument("--seed", type=int, default=None, help="Random seed for sampling (omit for a fresh sample each run)")
    p.add_argument("--use-llm", action="store_true", help="Also exercise Layer 2 (needs an API key configured)")
    p.add_argument("--dry-run", action="store_true", help="Report findings, do not write the review queue")
    p.add_argument("--include-out-of-scope", action="store_true",
                   help="Do not filter OUT_OF_SCOPE_SUBCATEGORIES (denial_of_wallet, supply_chain, "
                        "websocket_attack) — off by default to keep the review queue on-mission.")
    args = p.parse_args()

    seed = args.seed if args.seed is not None else int(datetime.now(timezone.utc).timestamp())
    exclude = set() if args.include_out_of_scope else OUT_OF_SCOPE_SUBCATEGORIES

    # 1. Sample seeds + generate offline variants (homoglyph/leetspeak/base64/passive-rewrite)
    seeds = load_seeds(ROOT / args.data_path, args.n_seeds, seed, exclude)
    if not seeds:
        logger.error("No attack seeds found in %s", args.data_path)
        return 1
    logger.info("Sampled %d attack seeds (random seed=%d)", len(seeds), seed)

    from ml.adversarial.attack_generator import AttackGenerator
    from ml.adversarial.variant_curator import VariantCurator

    generator = AttackGenerator(api_key=None, offline_fallback=True)
    generator._anthropic_available = False  # force deterministic offline mutations, no API cost
    variants = generator.generate_variants(seeds, n_variants_per_seed=args.n_variants)
    curated = VariantCurator().curate(variants, max_total=2000)
    logger.info("Generated %d raw variants -> %d after curation dedup", len(variants), len(curated))

    # 2. Run each variant through the LIVE Analyzer (the actual shipped surface)
    from memgar import Analyzer, MemoryEntry

    analyzer = Analyzer(use_llm=args.use_llm)
    missed: list[dict] = []
    caught = 0
    for v in curated:
        result = analyzer.analyze(MemoryEntry(content=v["text"]))
        if result.decision.name == "ALLOW":
            missed.append({**v, "risk_score_at_mine": result.risk_score})
        else:
            caught += 1
    logger.info("Live-Analyzer pass: %d caught, %d missed (false negatives)", caught, len(missed))

    if not missed:
        print(json.dumps({"seeds": len(seeds), "variants_tested": len(curated),
                           "caught": caught, "missed": 0}, indent=2))
        return 0

    # 3. Dedup misses against what's already known (gold + existing review queue)
    gold = json.loads((ROOT / args.gold_path).read_text(encoding="utf-8"))
    known_texts = [s["text"] for s in gold["samples"]]
    review_path = ROOT / args.review_queue_path
    if review_path.exists():
        existing_queue = json.loads(review_path.read_text(encoding="utf-8"))
        known_texts += [s["text"] for s in existing_queue.get("samples", [])]
    else:
        existing_queue = {"version": "1.0", "samples": []}

    genuinely_new = dedup_against(missed, known_texts, threshold=0.75)
    logger.info("%d misses are genuinely new (not already in gold/review-queue)", len(genuinely_new))

    by_category = Counter(m.get("category", "unknown") for m in genuinely_new)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seeds_sampled": len(seeds),
        "variants_tested": len(curated),
        "caught": caught,
        "missed_total": len(missed),
        "missed_genuinely_new": len(genuinely_new),
        "missed_by_category": dict(by_category),
        "sample_misses": [
            {"text": m["text"], "category": m.get("category"), "risk_score": m["risk_score_at_mine"]}
            for m in genuinely_new[:15]
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.dry_run or not genuinely_new:
        return 0

    # 4. Append to the review queue (NOT gold — a human/agent pass must confirm
    #    each miss is a real attack shape and not mislabeled/duplicate seed data
    #    before it's safe to merge into the strict gold gate).
    new_rows = [
        {
            "text": m["text"],
            "label": 1,
            "language": m.get("language", "en"),
            "category": m.get("category", "unknown"),
            "note": (
                f"mined=continuous_redteam; origin={m.get('origin', 'unknown')}; "
                f"seed_source={m.get('source', 'unknown')}; "
                f"risk_score_at_mine={m['risk_score_at_mine']}"
            ),
        }
        for m in genuinely_new
    ]
    existing_queue.setdefault("samples", [])
    existing_queue["samples"].extend(new_rows)
    existing_queue["version"] = existing_queue.get("version", "1.0")
    existing_queue["description"] = existing_queue.get(
        "description",
        "Boundary cases and mined false negatives — need human/agent review before merging into gold.",
    )
    existing_queue["schema"] = existing_queue.get("schema", {
        "text": "input string",
        "label": "1 = attack, 0 = benign",
        "language": "iso-639-1 (en | tr | ...)",
        "category": "memgar threat category or 'benign'",
        "note": "audit trail: mining origin + source + risk_score at mine time",
    })
    existing_queue["last_updated"] = datetime.now(timezone.utc).isoformat()
    review_path.write_text(json.dumps(existing_queue, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Appended %d new candidates to %s (total now %d)",
                len(new_rows), args.review_queue_path, len(existing_queue["samples"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
