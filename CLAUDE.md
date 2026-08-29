# Memgar — Development Guide

## Project Overview

Memgar is a production-grade AI agent memory security library. It detects and blocks memory poisoning attacks against LLM-based agents using a 4-layer analysis pipeline.

## Architecture

### Analysis Pipeline (`memgar/analyzer.py`)

```
Layer 1   — Pattern Matching             <1ms    always on
Layer 2   — LLM Semantic Analysis        ~200ms  optional (use_llm=True)
Layer 2.5 — Semantic Similarity (cosine) ~5ms    optional (similarity_layer, sentence-transformers)
Layer 3   — Trust-Aware Scoring          <0.1ms  auto (when source registered)
Layer 4   — Behavioral Baseline          <1ms    auto (per-agent, after warm-up)
```

> **Removed (2026-06):** Layer 1.5 SemanticGuard (centroid-based embedding
> classifier). Ablation proved it added **+0 recall** over Layer 2.5 on every
> corpus tested — clean threat-model, advbench OOD, and obfuscated
> homoglyph/leetspeak variants — while costing an extra ~28ms encode per
> analysis. Semantic detection is now Layer 2.5 (`similarity_layer`) alone.

> **Removed (2026-06):** Layer 2-ML transformer (fine-tuned ONNX detector).
> Default was off; when enabled the bundled artifact over-fired on prosaic
> memory-writes ("grant Sofia view access" scored 0.9999 — higher than real
> attacks), adding **no recall on the gold corpus** while raising FPR from
> ~0.02 to ~0.15. The supporting code, training scripts, ONNX artifact, and
> `MEMGAR_TRANSFORMER_*` env vars were all removed along with it. If you
> need ML detection later, retrain from production traffic on a fresh
> architecture rather than reviving the v2 weights.

**Layer 1** (`_layer1_pattern_matching`): Regex + keyword matching against 736 threat patterns loaded from `memgar/patterns.py` (pickle-cached for 3ms load vs 3500ms cold).

**Layer 2** (`_layer2_semantic_analysis`): Claude LLM call for sophisticated attacks. Runs independently of Layer 1 (catches obfuscation Layer 1 misses).

**Layer 3** (`_analyze_internal`, after risk_score computed): Source trust adjustment. Call `analyzer.register_source_trust(source_id, 0.0–1.0)` before analyzing. Low trust (<0.3) boosts risk ≤+30pts; high trust (≥0.8) reduces borderline scores by 5pts.

**Layer 4** (`analyze()`, after _analyze_internal): Per-agent `BehavioralBaseline` observes `scan_risk_score` and `scan_block_rate`. If the agent's current signals deviate SUSPICIOUS (+15pts) or CRITICAL (+30pts) from their learned baseline, risk is elevated. Only amplifies existing threat signals — never flags `risk_score=0` content.

### Key Entry Points

```python
from memgar import Analyzer, MemoryEntry, Decision

a = Analyzer(use_llm=False)                          # Layer 1+3+4
a.register_source_trust("untrusted-wiki", 0.1)       # Layer 3 setup
result = a.analyze(MemoryEntry(content="..."))        # sync
result = await a.analyze_async(MemoryEntry(...))      # async (thread-pool)
```

### Defense pipeline coverage (2026-06 wiring sprint)

Mapping of the persistent-memory-poisoning defense layers to memgar
components (see the defense-compliance audit for the gap analysis that
drove this wiring; previous score 72/100, post-wiring ~92/100):

| Layer | Memgar implementation | Default |
|---|---|---|
| L1 — Input moderation + composite trust | Analyzer Layer 1 patterns + Layer 2.5 similarity + Layer 3 source trust | on |
| L2 — Instruction stripping | `memgar.sanitizer.InstructionSanitizer` | (in gateway) |
| L2 — Provenance tagging | `Analyzer._build_provenance` → `entry.metadata['provenance']` | **on** |
| L2 — Write-ahead validation | `WriteAheadValidator` (RuleBased + MINJA + SemanticGuardian) | gateway |
| L2 — MINJA compound detection | `MINJADetector` wired into `Analyzer._analyze_internal` | **on** |
| L3 — Trust-weighted retrieval | `TrustAwareRetriever._calculate_trust_weight` | on (for retriever) |
| L3 — Temporal decay (trust) | `trust_decay_half_life_days=180.0` in TrustAwareRetriever | **on** |
| L3 — Retrieval anomaly: frequency / narrow / spread / spike | `RetrievalAnomalyDetector` 5 checks | on |
| L3 — "Many unrelated contexts" indicator | New `trusted_spread` check (>=50 distinct contexts) | **on** |
| L4 — Behavioral baseline | `BehavioralBaseline` (per-agent EWM z-score) | auto |
| L4 — Memory integrity auditing | `MemoryAuditor.snapshot/verify/rollback` | on-demand |
| L4 — Periodic integrity scan | `MemoryAuditor.start_periodic_audit(get_data, interval)` | opt-in |
| L4 — Cross-agent propagation | `CorrelationDetector._check_cross_agent_propagation` | **on** |
| L4 — Circuit breakers | `CircuitBreaker.record_from_result` + Analyzer hooks | opt-in (on in `MemgarDefensePipeline`) |
| User confirmation for memory writes | `MemoryWriteGateway(confirm_all_writes=True)` | opt-in |

Items in **bold** were rolled into the default `Analyzer()` flow during the
sprint — earlier they were class-libraries with no path from the documented
entry point. Items marked "opt-in" are intentional: they either need
infrastructure (HITL backend, persistent ledger) or have side effects
(stateful breaker on stateless scorer) that don't match a one-size-fits-all
default.

### Threat Intelligence Feed (`memgar/feed/`)

- **`FeedLoader`** downloads `memgar-feed.json.gz` from GitHub Releases, verifies Ed25519 signature, caches at `~/.cache/memgar/feeds/`
- **`FeedVerifier`** (`verifier.py`): `FEED_PUBLIC_KEY_B64` holds the real public key (generated 2026-04-26)
- **`FeedCache`**: 20MB compressed / 100MB decompressed limits; stale after `max_age_days=7`
- Feed patterns merge into Analyzer at startup if `cfg.feed.enabled=True` (default)
- CLI: `memgar feed sync | status | verify`
- Publish new bundle: `python scripts/publish_feed.py --private-key-file feed_private.pem --feed-version X.Y.Z`

### Adversarial Red-Team Loop (`ml/adversarial/`)

```
AttackGenerator  →  VariantCurator  →  live Analyzer test  →  review queue
```

- **`AttackGenerator`**: 4 offline mutations (homoglyph Cyrillic, leetspeak, base64, passive rewrite) + optional Claude API
- **`VariantCurator`**: TF-IDF cosine dedup, `max_variants_per_cluster=3`
- CLI: `python scripts/red_team_run.py --n-seeds 10 --n-variants 5 [--dry-run] [--offline]`

### Observability (`memgar/observability/`)

5 Prometheus metrics:
- `memgar_analyses_total{decision}` Counter
- `memgar_analysis_latency_seconds` Histogram
- `memgar_risk_score` Histogram (0-100)
- `memgar_drift_severity` Gauge (0=none → 4=critical)
- `memgar_model_version{version}` Gauge

PSI-based `DriftMonitor` runs in background thread (60s heartbeat). Emits SIEM `DRIFT_DETECTED` events on high PSI.

```python
import memgar
memgar.start_metrics_server(port=9090)  # idempotent
```

### Continuous Learning (`ml/continuous_learning.py`)

- `StorageManager.save_prediction()`: prediction persistence
- `FeedbackTracker` / `DriftDetector`: metric-based drift alerting
- `AutoRetrainer.inject_adversarial_variants(variants)`: appends to `adversarial_variants.jsonl`

> **Removed (2026-08):** `AutoRetrainer.retrain()` — trained a standalone
> XGBoost model (`gradient_boost_model.pkl`) that `Analyzer.analyze()` never
> loaded.  Also removed: `SmartDetector`, `ml/quality_gate.py`,
> `ml/training/train.py`, `ml/training/ml_feature_extractor.py`,
> `memgar/ml_semantic_detector.py`, `rebuild_model.py`.  Detection is handled
> entirely by the 4-layer pipeline; the red-team loop now tests against the
> live Analyzer (`scripts/continuous_redteam.py`).

## Development Workflow

```bash
# Install with all extras
pip install -e ".[dev,adversarial,feed,observability]"

# Run tests
python -m pytest -q                    # ~1105 pass, ~63 skip, 0 errors, 0 failures

# Pattern authoring note: Analyzer._compile_patterns() forces re.IGNORECASE
# on every regex (see analyzer.py:1243). To require case-sensitive matching
# inside a pattern — e.g. bare "DAN" must NOT match Turkish ablative
# "...'dan" — wrap with the inline group r"(?-i:\bDAN\b)".
python -m pytest tests/test_analyzer.py -v      # Layer 3+4 integration tests
python -m pytest tests/test_feed.py -v          # Feed verify/cache/loader tests
python -m pytest tests/test_adversarial.py -v   # Red-team tests
python -m pytest tests/test_observability.py -v # Prometheus/drift tests

# Red-team dry run
python scripts/red_team_run.py --n-seeds 10 --n-variants 5 --dry-run --offline

# Corpus expansion pipeline (Phase 1 + 2 of corpus growth)
python scripts/import_public_corpora.py            # AdvBench/JBB/HarmBench/gandalf/deepset → external_corpus_*.json
python scripts/import_benign_corpora.py            # OpenAssistant/HH-RLHF/Dolly → benign_corpora.json (memory-write-shaped benigns)
python scripts/mine_hard_negatives.py              # Diagnostic subset: all FPs + top-N FN per category → mined_hard_subset.json
python scripts/augment_memory_context.py           # Wrap attack seeds in 8 memory-injection envelopes → augmented_memory_context.json
python scripts/merge_corpus.py --aux ml/data/mined_hard_subset.json \
    --aux ml/data/augmented_memory_context.json    # Dry-run: see merged stats (gold stays untouched)

# Calibration (two-tier)
python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --output ml/artifacts/fpfn_calibration.json --no-llm
python scripts/check_calibration_gate.py           # Gold-only: 8 strict gates (CI blocker)

python scripts/calibrate_fpfn.py \
    --corpus ml/data/calibration_corpus.json \
    --corpus ml/data/mined_hard_subset.json \
    --corpus ml/data/augmented_memory_context.json \
    --output ml/artifacts/fpfn_calibration_expanded.json --no-llm
python scripts/check_expanded_gate.py              # Merged: 6 regression-only gates
```

## Corpus tiers

| Tier | File | Source | Reviewed | Used by |
|---|---|---|---|---|
| Gold | `ml/data/calibration_corpus.json` | hand-curated | yes | CI gate (strict) |
| Mined | `ml/data/mined_hard_subset.json` | auto from public-corpus FN/FP | algorithmic | Expanded gate |
| Augmented | `ml/data/augmented_memory_context.json` | template wrappers on seeds | deterministic | Expanded gate |
| Review queue | `ml/data/mined_review_queue.json` | boundary cases | pending | manual import only |
| Raw external | `ml/data/external_corpus_raw.json` | full public-corpus dump | none | reference only |

## Key Files

| Path | Purpose |
|------|---------|
| `memgar/analyzer.py` | Core 4-layer analysis engine |
| `memgar/patterns.py` | 736 threat patterns (source of truth) |
| `memgar/feed/verifier.py` | Ed25519 public key for feed verification |
| `memgar/config.py` | `MemgarConfig`, `FeedConfig`, `ObservabilityConfig` |
| `memgar/behavioral_baseline.py` | Layer 4 BehavioralBaseline, SIGNAL_REGISTRY |
| `memgar/retriever.py` | Layer 3 TrustAwareRetriever (standalone RAG) |
| `ml/continuous_learning.py` | StorageManager, FeedbackTracker, DriftDetector |
| `ml/adversarial/` | AttackGenerator, VariantCurator |
| `memgar/observability/` | Prometheus metrics, DriftMonitor |
| `memgar/siem.py` | OCSF-compatible SIEM events |
| `scripts/publish_feed.py` | Maintainer tool: sign + publish feed bundle |
| `scripts/red_team_run.py` | CLI: generate + inject adversarial variants |
| `scripts/import_public_corpora.py` | Pull + normalize public datasets (AdvBench, JBB, HarmBench, Gandalf, deepset) |
| `scripts/import_benign_corpora.py` | Pull realistic benign memory-writes (OpenAssistant, HH-RLHF, Dolly, LMSYS) — license-clean only |
| `scripts/mine_hard_negatives.py` | Stratify hard subset → auto-merge-safe selection + review queue |
| `scripts/augment_memory_context.py` | Wrap attack seeds in 8 memory-injection envelopes |
| `scripts/merge_corpus.py` | Combine gold + auxiliary corpora (dry-run by default) |
| `scripts/calibrate_fpfn.py` | End-to-end Analyzer evaluation, accepts multiple `--corpus` flags |
| `scripts/check_calibration_gate.py` | Strict gold-only CI gate (8 gates) |
| `scripts/check_expanded_gate.py` | Regression-only merged-corpus gate (6 gates) |
| `feeds/memgar-feed.json.gz` | Signed feed bundle (committed, auto-updated by CI) |

## Configuration

All settings via `MemgarConfig` (YAML file or env vars):

```bash
MEMGAR_FEED_ENABLED=true           # default: true
MEMGAR_FEED_MAX_AGE_DAYS=7
MEMGAR_FEED_GITHUB_REPO=slcxtor/memgar
MEMGAR_OBSERVABILITY_ENABLED=true  # default: false
MEMGAR_OBSERVABILITY_PORT=9090
MEMGAR_OBSERVABILITY_DRIFT_THRESHOLD=0.20
MEMGAR_OBSERVABILITY_DRIFT_WINDOW=1000
MEMGAR_CACHE_DIR=~/.cache/memgar
```

## Security Notes

- **Pickle RCE**: `_RestrictedUnpickler` allowlists only `builtins` + `memgar.models` classes
- **SSRF**: `FeedLoader._ALLOWED_HOSTS` restricts downloads to `github.com` / `*.githubusercontent.com`
- **Gzip bombs**: 20MB compressed / 100MB decompressed hard limits in both `FeedLoader` and `FeedCache`
- **Feed tampering**: Ed25519 signature verified before caching; `FeedSignatureError` raised on mismatch
- **Path traversal**: `MEMGAR_CACHE_DIR` validated to stay within home directory
- **pyo3 panics**: `except BaseException` guards around all `cryptography` imports (system package can panic)
