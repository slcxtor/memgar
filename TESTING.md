# Testing Guide

## Quick Start

```bash
# Install dev dependencies
pip install -e ".[dev,semantic,feed,observability,adversarial]"

# Run all tests
pytest

# Fast run (excludes slow load benchmarks)
pytest -q

# Verbose with details on failures
pytest -v --tb=short
```

---

## Test Suite Overview

The suite is one file per subsystem under `tests/`. Rather than duplicate the
listing here (it drifted badly enough to name five files that no longer exist),
read it from the tree:

```bash
ls tests/
python -m pytest --collect-only -q | tail -1
```

Landmarks:

| File | Covers |
|---|---|
| `test_analyzer.py` | 4-layer pipeline, Layer 3+4 integration |
| `test_cli_commands.py` | Every CLI entry point, end to end through click |
| `test_normalization_integrity.py` | De-obfuscation must not corrupt the values it scans |
| `test_feed.py` | Threat feed — loader, cache, Ed25519 verifier |
| `test_observability.py` | Prometheus metrics, drift monitor |
| `test_adversarial.py` | Red-team loop — AttackGenerator, VariantCurator |
| `test_continuous_learning.py` | AutoRetrainer, StorageManager, DriftDetector |
| `test_load.py` | Throughput benchmarks (marked `slow`, deselected by default) |

**Current totals:** 1,143 passed, 64 skipped, 1 deselected (slow). Skips are
optional-dependency paths — `sentence-transformers` for Layer 2.5, and the
Ed25519 tests when the system `cryptography` build panics under pyo3.

---

## Running Specific Tests

```bash
# Single module
pytest tests/test_hunter.py -v

# Single test class
pytest tests/test_memory_store.py::TestPersistentMemoryStore -v

# Single test
pytest tests/test_analyzer.py::TestLayer3TrustScoring::test_low_trust_boosts_risk -v

# By keyword
pytest -k "hunter and sqlite" -v
pytest -k "retroactive or bulk_scan" -v

# Exclude slow benchmarks (default via pyproject.toml)
pytest -m "not slow"

# Run slow benchmarks explicitly
pytest -m slow -v
```

---

## Test Categories

### Core Analysis (test_analyzer.py)
Covers:
- Layer 1 pattern matching on 22+ attack categories
- Layer 2 LLM integration (mocked in CI)
- Layer 3 trust score adjustment (low/high trust)
- Layer 4 behavioral baseline (SUSPICIOUS / CRITICAL deviation)
- `analyze_async()` thread safety
- Decision thresholds (ALLOW / WARN / BLOCK)

### Hunter Mode (test_hunter.py — 85 tests)
Covers:
- Background scan thread lifecycle (`start`, `stop`, `is_running`)
- `from_sqlite()` — real SQLite database fixture
- `from_jsonl()` — JSONL file fixture
- `from_list()` — in-memory string list
- `scan_now()` — synchronous immediate scan
- `report()` — pretty-print output
- Context manager (`with MemoryHunter.from_list(...) as h`)
- `on_threat` callback — called for each detected threat
- Stats accuracy (`total_scanned`, `threats_found`, `scan_cycles`)
- Cache TTL — clean entries re-scanned after `rescan_clean_after_seconds`
- Provider exceptions — crash in provider doesn't crash hunter thread

### Memory Store (test_memory_store.py — 35 tests)
Covers:
- `MemoryStore` dedup by source_id and content hash
- `MemoryStore` TTL eviction and max_entries ring buffer
- `PersistentMemoryStore` JSONL write/read
- Survival across restart (save → new instance → load)
- `max_age_days` filtering on load
- `compact()` rewrites file to current entries only
- Malformed JSONL lines skipped gracefully
- `bulk_scan()` retroactive scanning of historical entries
- `bulk_scan()` threshold filtering
- `bulk_scan()` exported from `memgar` top-level

### Zero-Shot Generalization (test_zero_shot_generalization.py — 61 tests)
Covers:
- Per-category recall ≥ 60% for 10 novel attack categories
- FPR = 0% on 20 benign texts
- Aggregate gate: overall recall ≥ 60%
- Benchmark script integrity (callable, returns dict, correct structure)
- Dataset sanity (no benign text should score ≥ 90 on Layer 1)

### Real-world attack coverage
`test_real_world_attacks.py` (20), `test_documented_attacks.py` (13),
`test_security_deep.py` (18), `test_security_hardening.py` (12) and
`test_evasion_hardening.py` (8) carry real attack strings across:
- Prompt injection, IBAN fraud, credential theft, data exfiltration
- Sleeper payloads, code injection, supply chain, DoW
- MINJA variants, AgentPoison, MemoryGraft patterns
- Multi-stage attacks, social engineering, authority escalation

---

## Writing New Tests

### Adding a threat detection test

```python
def test_my_new_attack_detected():
    from memgar import Analyzer, MemoryEntry, Decision
    a = Analyzer(use_llm=False)
    result = a.analyze(MemoryEntry(content="<attack string here>"))
    assert result.decision == Decision.BLOCK
    assert result.risk_score >= 70
```

### Adding a benign (non-regression) test

```python
def test_my_benign_not_flagged():
    from memgar import Analyzer, MemoryEntry, Decision
    a = Analyzer(use_llm=False)
    result = a.analyze(MemoryEntry(content="User prefers dark mode"))
    assert result.decision == Decision.ALLOW
    assert result.risk_score < 30
```

### Adding a hunter test

```python
def test_my_hunter_feature():
    from memgar.hunter import MemoryHunter
    from memgar.config import HunterConfig

    cfg = HunterConfig(scan_interval_seconds=9999)  # prevent auto-scan
    with MemoryHunter.from_list(["some content"], config=cfg) as h:
        stats = h.scan_now()
        assert stats.total_scanned >= 1
```

---

## Coverage

```bash
# HTML coverage report
pytest --cov=memgar --cov-report=html
open htmlcov/index.html

# Terminal summary
pytest --cov=memgar --cov-report=term-missing

# With branch coverage
pytest --cov=memgar --cov-report=html --cov-branch
```

---

## CI / GitHub Actions

Tests run on every push via `.github/workflows/`. The matrix covers Python 3.9, 3.10, 3.11, 3.12.

Skipped in CI:
- 3 Ed25519 tests — pyo3 backend panics in the CI runner environment (known limitation)
- `slow` marked benchmarks — excluded via `pytest -m "not slow"`

To run the full suite locally including benchmarks:
```bash
pytest -m slow -v tests/test_load.py
```

---

## Troubleshooting Common Test Failures

### `ModuleNotFoundError: No module named 'sentence_transformers'`
```bash
pip install "memgar[semantic]"
```

### Hunter tests timing out
Hunter uses `threading.Event.wait()` internally. If `stop(timeout=2.0)` hangs, a thread leak from a previous test may be holding the event. Run the specific test file in isolation: `pytest tests/test_hunter.py -v`.

### `test_verify_valid_signature_with_real_keypair` skipped
Expected — Ed25519 requires a working pyo3/cffi backend. On this system, `_cffi_backend` is missing. The test is correctly guarded with `requires_crypto`.

### ML tests skipping
Run `python rebuild_model.py` first to generate `ml/artifacts/gradient_boost_model.pkl`.

### False positive in a new benign test
Check `analyzer.risk_score` and `result.threats` to see which patterns fired. If a pattern is overly broad, open a PR with the false positive string added to the test suite and the pattern refined in `patterns.py`.
