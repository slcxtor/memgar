# Memgar Public Benchmark

- generated: `2026-06-01T19:24:45Z`
- mode: `quick (100/corpus, default) threat-model-only`
- seed: `42`
- analyzer config: `Analyzer(use_llm=False)`

## Attack recall per corpus

| corpus | size | caught (BLOCK + QUARANTINE) | recall | p50 ms | p95 ms |
|---|---|---|---|---|---|
| memgar_threat_model | 74 | 70 | **0.946** | 126.93 | 198.54 |
| **overall** | **74** | **70** | **0.946** | — | — |

## Benign FPR per corpus

| corpus | size | blocked (false positive) | FPR | p50 ms | p95 ms |
|---|---|---|---|---|---|
| memgar_threat_model_benign | 50 | 3 | **0.060** | 34.69 | 106.33 |
| **overall** | **50** | **3** | **0.060** | — | — |

## Detection-layer contribution (attack corpus only)

Counts the analyses where the named layer fired at least once. An attack often trips several layers; rows can sum to more than the corpus size.

| layer | hits | of |
|---|---|---|
| `pattern_matching` | 74 | 74 |
| `correlation_detector` | 67 | 74 |
| `ensemble_voter` | 58 | 74 |
| `transformer_ml` | 53 | 74 |
| `similarity_layer_elevated` | 16 | 74 |
| `similarity_layer` | 7 | 74 |
| `stego_detector` | 3 | 74 |
