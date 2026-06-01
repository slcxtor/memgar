# Memgar Ablation Report

- generated: `2026-06-01T19:26:44Z`
- mode: `quick (100/corpus, default) threat-model-only`
- seed: `42`

## Overall recall / FPR per analyzer config

| config | attack N | caught | recall | benign N | FPR |
|---|---|---|---|---|---|
| `L1_patterns_only` | 74 | 66 | **0.892** | 50 | **0.060** |
| `L1_plus_similarity` | 74 | 66 | **0.892** | 50 | **0.060** |
| `L1_plus_ml` | 74 | 70 | **0.946** | 50 | **0.060** |
| `full_stack` | 74 | 70 | **0.946** | 50 | **0.060** |

### `L1_patterns_only` — per-corpus

| corpus | size | caught | rate | kind |
|---|---|---|---|---|
| memgar_threat_model | 74 | 66 | 0.892 | attack |
| memgar_threat_model_benign | 50 | 3 | 0.060 | benign |

### `L1_plus_similarity` — per-corpus

| corpus | size | caught | rate | kind |
|---|---|---|---|---|
| memgar_threat_model | 74 | 66 | 0.892 | attack |
| memgar_threat_model_benign | 50 | 3 | 0.060 | benign |

### `L1_plus_ml` — per-corpus

| corpus | size | caught | rate | kind |
|---|---|---|---|---|
| memgar_threat_model | 74 | 70 | 0.946 | attack |
| memgar_threat_model_benign | 50 | 3 | 0.060 | benign |

### `full_stack` — per-corpus

| corpus | size | caught | rate | kind |
|---|---|---|---|---|
| memgar_threat_model | 74 | 70 | 0.946 | attack |
| memgar_threat_model_benign | 50 | 3 | 0.060 | benign |
