# 4-Layer pipeline

Each layer contributes a signal; `Analyzer` combines them into a single
`risk_score` (0–100) and a `Decision`. The order matters — Layer 1 must run
first, Layer 4 must run last, but everything in between is independent.

## Call order

```python
result = analyzer.analyze(MemoryEntry(content="..."))
# 1. _layer1_pattern_matching     — regex/keyword
# 2. _semantic_guard.score()      — embedding similarity
# 3. _layer2_semantic_analysis    — optional LLM
# 4. _analyze_internal            — combine + apply Layer 3 trust
# 5. _behavioral_baseline.scan    — Layer 4 anomaly
# 6. fail_close escalation        — final ALLOW → QUARANTINE if degraded
```

## Risk score combination

The combiner is conservative: it takes the **max** of layer scores rather
than summing, and applies bounded adjustments from Layer 3/4. This prevents
runaway "everything looks slightly suspicious" inputs from reaching `block`.

```
risk_score = max(
    layer1_pattern_score,
    layer1_5_semantic_score * 0.8,
    layer2_llm_score,
)
+ layer3_trust_adjustment   (range -5 to +30)
+ layer4_baseline_deviation (0, +15, or +30)
```

## Pickle-cached pattern load

Importing `memgar.patterns` cold takes ~3500ms because the module defines
770+ `Threat` dataclasses with multi-line examples. A pickle cache at
`~/.cache/memgar/patterns_v1.pkl` keyed by the file's SHA-256 drops this to
~3ms on warm starts and is rebuilt automatically when `patterns.py` changes.

## Layer 1.5 health visibility

When `sentence-transformers` is not installed or the centroids file is
missing, the layer:

1. Logs a single `WARNING` ("Layer 1.5 disabled: reason …, fix: …").
2. Future calls return `score=0.0` instantly.
3. `health()` returns `{status: "degraded", reason, fix_hint}`.
4. `Analyzer.health_check()` aggregates the disabled state into the per-layer
   report so operators can wire it into Prometheus / alerts.

The same pattern is implemented for `FeedLoader` — no silent zero scoring
anywhere in the pipeline.

## Trust-aware Layer 3

Source trust is an explicit operator decision — memgar does not auto-learn
trust. Register sources at startup:

```python
a = Analyzer()
a.register_source_trust("openai-api",       0.95)   # high trust
a.register_source_trust("github-actions",   0.85)
a.register_source_trust("user-form",        0.40)   # neutral
a.register_source_trust("untrusted-wiki",   0.10)   # low trust
a.register_source_trust("anonymous-input",  0.05)   # very low
```

Borderline risk_score (40-60) gets multiplied by `(1 + (1 - trust) * 0.5)`
so untrusted sources cross the `block` threshold more readily. High-trust
sources get a 5-point reduction to absorb minor pattern noise.

## Behavioral baseline Layer 4

Per-agent EMA on `scan_risk_score` and `scan_block_rate`:

- After 50 scans the baseline is established.
- Each subsequent scan updates the EMA with α=0.05.
- If the current 5-scan window's risk deviates >2σ from the baseline,
  Layer 4 raises `severity=SUSPICIOUS` (+15pts).
- If >3σ, `severity=CRITICAL` (+30pts).
- Layer 4 never flags content that scored 0 — it only amplifies existing
  signal.
