# Memgar Public Benchmark

This document records honest, reproducible numbers for the memgar
analyzer against externally-authored attack and benign corpora. The
corpora live under `ml/data/_corpus_cache/` and are pulled by
`scripts/import_public_corpora.py` / `scripts/import_benign_corpora.py`
— license-clean dumps only.

These numbers come from running:

```bash
python scripts/public_benchmark.py --quick \
    --output-md  BENCHMARK.md \
    --output-json benchmarks/quick_<date>.json
```

Anyone with the repo checked out can re-run this command and reproduce
the table below (seed-locked at 42; the same 100 attack samples will be
drawn from every corpus regardless of which machine runs the bench).

Run `--full` instead of `--quick` to evaluate the entire cached corpus
(~30 minutes on a 4-CPU box with the ONNX INT8 model warm).

---

- generated: `2026-06-01T18:44:17Z`
- mode: `quick (100/corpus)`
- seed: `42`
- analyzer config: `Analyzer(use_llm=False)`

## Attack recall per corpus

| corpus | size | caught (BLOCK + QUARANTINE) | recall | p50 ms | p95 ms |
|---|---|---|---|---|---|
| advbench | 100 | 47 | **0.470** | 158.62 | 227.23 |
| jbb_harmful | 100 | 36 | **0.360** | 153.54 | 212.18 |
| harmbench | 100 | 30 | **0.300** | 155.86 | 220.0 |
| gandalf | 100 | 91 | **0.910** | 135.44 | 201.09 |
| trustairlab_jb | 100 | 83 | **0.830** | 972.77 | 2366.15 |
| **overall** | **500** | **287** | **0.574** | — | — |

## Benign FPR per corpus

| corpus | size | blocked (false positive) | FPR | p50 ms | p95 ms |
|---|---|---|---|---|---|
| jbb_benign | 100 | 3 | **0.030** | 48.3 | 81.53 |
| openassistant | 100 | 23 | **0.230** | 227.47 | 1598.59 |
| dolly | 100 | 0 | **0.000** | 28.67 | 100.29 |
| **overall** | **300** | **26** | **0.087** | — | — |

## Detection-layer contribution (attack corpus only)

Counts the analyses where the named layer fired at least once. An attack
often trips several layers; rows can sum to more than the corpus size.

| layer | hits | of |
|---|---|---|
| `pattern_matching` | 496 | 500 |
| `correlation_detector` | 283 | 500 |
| `ensemble_voter` | 227 | 500 |
| `transformer_ml` | 151 | 500 |
| `similarity_layer` | 60 | 500 |
| `similarity_layer_elevated` | 52 | 500 |
| `sliding_window` | 36 | 500 |
| `whitelist` | 4 | 500 |
| `stego_detector` | 1 | 500 |

---

## Reading these numbers honestly

Memgar's hand-curated **gold corpus** reports 97.5 % attack recall at
5.6 % FPR (see `scripts/check_calibration_gate.py`). The public-corpus
numbers above are deliberately harder:

- They were not curated by the memgar authors.
- The attack corpora were not part of the v2 transformer training data
  (no overlap with `ml/data/training_v2/train.jsonl`).
- AdvBench, JailbreakBench, and HarmBench are written to evade naive
  pattern detectors — they look like target *goals*, not the surface
  templates regexes catch.
- Gandalf and TrustAIR JB resemble real prompt-injection traffic, so
  patterns + similarity + ML overlap on most rows.

What the numbers say in plain language:

| dataset | what it means for memgar |
|---|---|
| **Gold (in-house)** 0.975 / 0.056 | The setup an aligned customer would tune to. |
| **Gandalf + TrustAIR** ~0.87 mean | Real attacker-shaped prompts. Strong. |
| **AdvBench / JBB / HarmBench** ~0.38 mean | Adversarial goals written by red-teamers. Memgar misses two-thirds; **deploy with input-side defenses, never as a sole barrier**. |
| **OpenAssistant FPR** 0.23 | Long, instruction-shaped benign chats trigger Layer 1 patterns. Production tuning needs a deployment-specific whitelist. |
| **Dolly / JBB benign FPR** 0.0 – 0.03 | Short, prosaic benigns are safe; the gate keeps them under 30 ms. |

Both signals matter. The gold gate confirms that the curated production
workload stays clean; the public bench tells a prospective design
partner what to expect on out-of-distribution attacker text.

## Per-layer ablation (planned)

The current benchmark reports the *combined* analyzer verdict. A future
revision of `public_benchmark.py` will add `--ablate` to report
`Layer 1` / `Layer 1 + 1.5` / `Layer 1 + 1.5 + 2.5` / full-stack recall
side-by-side so an external reviewer can see what each layer contributes.

## Reproducing

```bash
git clone https://github.com/slcxtor/memgar
cd memgar
pip install -e ".[ml,semantic]"

# pull cached public corpora (one-time, ~30 MB)
python scripts/import_public_corpora.py
python scripts/import_benign_corpora.py

# quick run (~5 min on 4 CPUs, sampled 100/corpus, seed-locked)
python scripts/public_benchmark.py --quick

# paper-grade run (~30 min, all rows)
python scripts/public_benchmark.py --full \
    --output-md BENCHMARK.full.md \
    --output-json benchmarks/full_$(date +%F).json
```

All outputs are deterministic given `--seed`.
