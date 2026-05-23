#!/usr/bin/env python3
"""Grow the gold calibration corpus to a statistically meaningful size.

The gold corpus had 55 benign samples, so a measured benign FPR of 0.000
carried a 95 %-confidence upper bound of ~6.5 % — not enough to claim
production-grade precision. This script enlarges the *benign* side with
curated, realistic memory-write samples (easy preferences AND hard
trigger-word-adjacent negatives) drawn deterministically from the
authored FP-stress set (`benign_calibration_large.json`).

Labels reflect ground truth, not analyzer output: a sample is included
because it is genuinely benign, never because the detector happens to
pass it. This keeps the gate honest — if precision regresses, the gold
FPR rises and the gate notices.

Attacks are left untouched (recall is already strong and the attack tier
is curated separately). Existing samples are preserved verbatim.

    python scripts/grow_gold_corpus.py                 # benign -> ~250
    python scripts/grow_gold_corpus.py --benign-target 250
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
GOLD = ROOT / "ml" / "data" / "calibration_corpus.json"
STRESS = ROOT / "ml" / "data" / "benign_calibration_large.json"

# Lead-ins / closers the generator prepends — strip them to derive a
# stable "core key" so we can cap near-identical variants.
_LEADS = ["hi team,", "quick note:", "for future reference,", "just so you know,",
          "please remember:", "fyi —", "fyi -", "heads up,", "merhaba,",
          "kısa not:", "bilgin olsun,", "i̇leride lazım olur:", "lütfen hatırla:"]
_CLOSERS = ["thanks!", "appreciate it.", "no rush.",
            "let me know if that's a problem.", "that's all for now.",
            "teşekkürler.", "acelesi yok.", "şimdilik bu kadar."]


def _core_key(text: str) -> str:
    t = text.strip().lower()
    for lead in _LEADS:
        if t.startswith(lead):
            t = t[len(lead):].strip()
            break
    for c in _CLOSERS:
        if t.endswith(c):
            t = t[: -len(c)].strip()
    t = re.sub(r"[^\w\s]", "", t)
    return " ".join(t.split()[:6])


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--benign-target", type=int, default=250,
                    help="desired total benign count in the grown gold corpus")
    ap.add_argument("--cap-per-core", type=int, default=4,
                    help="max near-identical variants per template core")
    args = ap.parse_args()

    gold = json.loads(GOLD.read_text(encoding="utf-8"))
    samples: List[Dict] = gold["samples"]
    existing_texts = {s["text"] for s in samples}
    n_attack = sum(1 for s in samples if s["label"] == 1)
    n_benign = sum(1 for s in samples if s["label"] == 0)

    stress = json.loads(STRESS.read_text(encoding="utf-8"))["samples"]

    need = max(0, args.benign_target - n_benign)
    core_counts: Dict[str, int] = {}
    # Pre-seed core counts from existing benign so we don't over-represent.
    for s in samples:
        if s["label"] == 0:
            core_counts[_core_key(s["text"])] = core_counts.get(_core_key(s["text"]), 0) + 1

    added = 0
    for s in stress:  # stress file is already shuffled + seeded → deterministic
        if added >= need:
            break
        text = s["text"]
        if text in existing_texts:
            continue
        key = _core_key(text)
        if core_counts.get(key, 0) >= args.cap_per_core:
            continue
        samples.append({"text": text, "label": 0,
                        "language": s.get("language", "en"),
                        "category": s.get("category", "benign")})
        existing_texts.add(text)
        core_counts[key] = core_counts.get(key, 0) + 1
        added += 1

    gold["samples"] = samples
    gold["version"] = "1.1.0"
    gold["description"] = (gold.get("description", "").split(" | ")[0]
                           + " | grown 2026-05 with curated realistic benign "
                           "memory-writes (easy + hard trigger-adjacent "
                           "negatives) for statistically meaningful FPR")
    gold["grown_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    GOLD.write_text(json.dumps(gold, ensure_ascii=False, indent=2),
                    encoding="utf-8")

    new_benign = sum(1 for s in samples if s["label"] == 0)
    print(f"Gold corpus grown: benign {n_benign} -> {new_benign} "
          f"(+{added}), attacks {n_attack} (unchanged). "
          f"Total {len(samples)} samples.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
