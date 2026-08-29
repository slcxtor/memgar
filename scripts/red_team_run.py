#!/usr/bin/env python3
"""
Red-team adversarial loop runner.

Generates obfuscated attack variants from seed data, curates them,
and tests them against the live Analyzer (the actual shipped detection
surface).  Variants that slip through are printed as a report.

For a more thorough loop with review-queue persistence, use
``continuous_redteam.py`` instead.

Usage:
    python scripts/red_team_run.py --n-seeds 10 --n-variants 5
    python scripts/red_team_run.py --offline --dry-run      # CI-safe smoke test
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("red_team")


def load_seeds(data_path: Path, n: int, seed: int = 42) -> list[dict]:
    if not data_path.exists():
        logger.error("Training data not found: %s", data_path)
        return []
    with data_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    attacks = [row for row in data if row.get("label") == 1]
    rng = random.Random(seed)
    return rng.sample(attacks, min(n, len(attacks)))


def main() -> int:
    parser = argparse.ArgumentParser(description="Memgar red-team adversarial loop")
    parser.add_argument("--n-seeds", type=int, default=10, help="Number of seed attacks to sample")
    parser.add_argument("--n-variants", type=int, default=5, help="Variants per seed")
    parser.add_argument("--data-path", default="ml/data/training_data.json")
    parser.add_argument("--dry-run", action="store_true", help="Generate variants, skip live-analyzer test")
    parser.add_argument("--offline", action="store_true", help="Force offline template mutations")
    parser.add_argument("--max-total", type=int, default=500, help="Max curated variants")
    args = parser.parse_args()

    # 1. Load seeds
    seeds = load_seeds(Path(args.data_path), args.n_seeds)
    if not seeds:
        logger.error("No attack seeds found — aborting")
        return 1
    logger.info("Loaded %d seed attacks", len(seeds))

    # 2. Generate variants
    from ml.adversarial.attack_generator import AttackGenerator

    api_key = None if args.offline else os.environ.get("ANTHROPIC_API_KEY")
    generator = AttackGenerator(
        api_key=api_key,
        offline_fallback=True,
    )
    if args.offline:
        generator._anthropic_available = False

    variants = generator.generate_variants(seeds, n_variants_per_seed=args.n_variants)
    logger.info("Generated %d raw variants", len(variants))

    # 3. Curate
    from ml.adversarial.variant_curator import VariantCurator

    curator = VariantCurator()
    curated = curator.curate(variants, max_total=args.max_total)
    logger.info("Curated down to %d unique variants", len(curated))

    if args.dry_run:
        print(json.dumps({"dry_run": True, "curated_count": len(curated)}, indent=2))
        return 0

    # 4. Test against the live Analyzer (the actual shipped detection surface)
    from memgar import Analyzer, MemoryEntry

    analyzer = Analyzer(use_llm=False)
    missed: list[dict] = []
    caught = 0
    for v in curated:
        result = analyzer.analyze(MemoryEntry(content=v["text"]))
        if result.decision.name == "ALLOW":
            missed.append({**v, "risk_score": result.risk_score})
        else:
            caught += 1

    report = {
        "seeds_sampled": len(seeds),
        "variants_tested": len(curated),
        "caught": caught,
        "missed": len(missed),
        "sample_misses": [
            {"text": m["text"][:200], "category": m.get("category"), "risk_score": m["risk_score"]}
            for m in missed[:10]
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
