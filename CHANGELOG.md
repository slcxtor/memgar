# Changelog

All notable changes to Memgar are documented here.

---

## [1.0.0] — 2026-05-19

First stable release. The API contract under `memgar/` is now considered
stable; breaking changes will be reserved for major versions.

### Highlights since 0.5.6

This release consolidates ~3 weeks of work across the threat library,
the memory layer, integrations, observability, and the operational
pipeline. Notable additions:

**Threat library (746 → 807 patterns, +61)**

- New `XSESS-*` family (12 patterns) — cross-session persistence:
  survive-restart directives, long-term store implants, anchor tokens,
  TTL/eviction evasion, embedding-layer stowaways, snapshot rehydration
  tampering, self-replicating memory worms, scheduled re-injection
- New `VECNN-*` family (12 patterns) — vector-DB nearest-neighbor
  attacks: cluster injection, HotFlip/TextFooler/BERT-Attack,
  top-K saturation, metadata-filter bypass, cross-namespace bleeding,
  re-ranker override, chunk-boundary smuggling, HyDE hijack
- New `MAGENT-*` family (12 patterns) — multi-agent contamination:
  broadcast-to-all, shared-memory implant, A2A message injection,
  supervisor spoof, handoff hijack, sybil voting, cross-tenant bridging

**Memory layer**

- `MemoryVault` snapshots now ship with a Merkle-tree root and
  `merkle_proof(entry_id)` method — O(log N) inclusion proofs against
  the recorded root, suitable for selective disclosure to auditors
- `MerkleTree` (pure-stdlib) for the integrity backbone
- `ReplayForensics` — cross-snapshot provenance, lineage, cohorts,
  session timelines
- `EmbeddingAnomalyDetector` — Welford-based centroid + k-NN density
  + cross-cluster collision detection for the `VECNN-*` family

**CLI**

- `memgar memory list / inspect / diff / verify / rollback / replay /
  trace / cohort` — 8 forensic subcommands. JSON output on every one,
  consistent exit-code contract (0 ok / 1 user / 2 integrity)

**Integrations (+6 wrappers)**

- `MemgarMem0Guard` — Mem0 memory layer
- `MemgarLettaGuard` — Letta (formerly MemGPT) memory-centric agents
- `MemgarPineconeIndex`, `MemgarChromaCollection`, `MemgarQdrantClient`,
  `MemgarWeaviateCollection` — drop-in security shells for the four
  leading vector DBs. All four share a `VectorStoreSecurityShell` with
  consistent BLOCK / SANITIZE / AUDIT_ONLY write policies and
  consistent `memgar_risk_score` / `memgar_decision` / `memgar_threat_ids`
  metadata on reads

**Threat-intel pipeline**

- `.github/workflows/feed-publish.yml` — weekly automated signed feed
  release (Mon 06:00 UTC). Ed25519-signed, verified locally before
  publish, attached to a GitHub Release for client `feed sync`
- `.github/workflows/threat-intel-sync.yml` — weekly external-source
  sync (Thu 04:00 UTC) from MITRE ATT&CK, NVD CVE, OWASP Top-10-LLM,
  four curated public jailbreak repos, four HuggingFace datasets.
  Opens a single curator-review PR per run
- Feed signing key rotated to a fresh Ed25519 pair (PR #63)

**Documentation**

- `docs/threats/kill-chain.md` — seven-phase memory-poisoning TTP
  framework (Reconnaissance → Preparation → Injection → Persistence
  → Lateral Movement → Activation → Impact)
- `docs/architecture/integrity.md` — Merkle + replay + anomaly design
- `docs/operations/forensics.md` — CLI runbook with incident-response
  playbook
- `docs/operations/threat-feed-pipeline.md` — maintainer runbook
- `docs/operations/threat-intel-pipeline.md` — curator runbook
- `docs/integration/memory-frameworks.md` — per-vendor quickstart
- Obsidian-style theme refresh across the whole site

**Code quality + CI**

- `.github/workflows/lint.yml` — ruff (I001 blocking) + bandit
  (high/high blocking). Bandit High severity: 4 → **0**
- ruff F401 cleanup: 321 → 23 across 80+ files
- `_GraphUnpickler` annotated with `# nosec B403` + allowlist docstring
- API-key placeholders standardised: `sk-ant-...` → `<your-anthropic-key>`

### Fixed

- `SIM-001` false positive: similarity-layer thresholds raised
  (`threat_threshold` 0.4 → 0.55, `quarantine_threshold` 0.34 → 0.45)
  so benign phrases like "Customer requested weekly reports" no longer
  quarantine. Genuine attacks remain blocked by Layer 1 patterns at
  Severity CRITICAL/HIGH.

### Removed

- Nothing. This release is additive across all surfaces.

### Honest notes

- Calibration is reported on **two corpora**:
  - **Gold** (95 attacks + 49 benign, hand-curated): ≈ 80 % recall,
    ≈ 9 % FPR. This is the public baseline.
  - **Expanded** (386 attacks + 78 benign — gold + mined public corpora
    + memory-context augmented templates): ≈ 79 % recall, ≈ 36 % FPR.
    The mined and augmented samples are programmatically generated, not
    hand-reviewed, so the decision boundary is fuzzier. CI's expanded
    gate currently reports *"no threshold satisfies the constraints —
    corpus too small or model too weak"* — this is a known regression
    surface, not a code bug. It tracks broader drift over time.
- No public benchmark for memory poisoning exists yet; treat all of
  the above as preliminary
- Not third-party audited
- Production deployments: pre-1.0 reach unknown. First PyPI release
  was 2026-05-18; install volume is just starting

### Upgrading from 0.5.x

`pip install --upgrade memgar`. No deprecations, no breaking changes
in the public API surface. The feed signing key was rotated, so the
first `memgar feed sync` after upgrade pulls a freshly signed bundle.

---

## [0.5.6] — 2026-05-03

### Fixed
- **Module import bug** — `memgar/forensics`, `memgar/frameworks/__init__`, `memgar/frameworks/langchain_deep`, and `memgar/frameworks/llmaindex.deep` were missing `.py` extensions, causing silent `ImportError` on all forensics and framework integration imports. All 32 public API classes now resolve correctly.
- `MemgarQueryEngineSecurity` and related LlamaIndex exports were silently `None` due to a filename typo (`llmaindex` → `llamaindex`).

### Changed
- All 5 documentation files (`ARCHITECTURE.md`, `DEPLOYMENT.md`, `ML_SYSTEM.md`, `DEPENDENCIES.md`, `TESTING.md`) rewritten with complete content.
- `README.md` updated to cover MemoryHunter, PersistentMemoryStore, `bulk_scan()`, and ML-enhanced detection. Removed stale placeholder sections.
- Added `SECURITY.md` with responsible disclosure policy and scope.

---

## [0.5.5] — 2026-05-02

### Added
- **MemoryHunter** (`memgar/hunter.py`) — background daemon thread for continuous memory scanning
  - Scans the attached memory store every `scan_interval_seconds` (default 60s)
  - `start_hunter(analyzer)` — one-call attach-and-start shortcut
  - `MemoryHunter.from_sqlite(db_path, table, column)` — connect to any SQLite database
  - `MemoryHunter.from_jsonl(path)` — connect to a JSONL file
  - `MemoryHunter.from_list(entries)` — connect to an in-memory list
  - `scan_now()` — synchronous immediate scan, returns `HunterStats`
  - `report()` — pretty-print current threat/scan stats to terminal
  - Context manager support: `with MemoryHunter.from_sqlite(...) as h:`
  - `on_threat` callback: `fn(entry, result)` called on each detected threat
  - Per-entry scan cache with TTL — clean entries re-examined after `rescan_clean_after_seconds`
- **MemoryStore** (`memgar/memory_store.py`) — thread-safe bounded in-memory ring buffer
  - Deduplication by `source_id` (priority) or SHA-256[:24] content hash
  - LRU eviction at `max_entries`; optional TTL eviction via `ttl_seconds`
- **PersistentMemoryStore** — disk-backed JSONL store that survives restarts
  - Appends every `add()` call to disk atomically
  - Loads full history on `__init__` (filtered by `max_age_days`)
  - `compact()` — rewrites JSONL file keeping only current in-memory entries
  - Enables retroactive scanning of entries from months ago
- **`bulk_scan()`** — one-shot retroactive scan of any `List[MemoryEntry]`
  - Load from database, CSV, or any external source and scan without infrastructure
  - `threshold` parameter (0.0–1.0) controls sensitivity
  - Returns `List[ThreatResult]` with `entry`, `risk_score`, `decision`, `threats`, `explanation`
- **`Analyzer(memory_store=...)`** — `Analyzer` now accepts an optional `memory_store` parameter; every analyzed entry is automatically captured
- **`HunterConfig`** dataclass — full configuration for MemoryHunter via `MemgarConfig.hunter` or env vars: `MEMGAR_HUNTER_ENABLED`, `MEMGAR_HUNTER_SCAN_INTERVAL_SECONDS`, `MEMGAR_HUNTER_RESCAN_CLEAN_AFTER_SECONDS`, `MEMGAR_HUNTER_ALERT_THRESHOLD`, `MEMGAR_HUNTER_MAX_ENTRIES_PER_SCAN`

---

## [0.5.4] — 2026-05-01

### Added
- **SemanticGuard** (`memgar/semantic_guard.py`) — Layer 1.5 hybrid embedding detector
  - `all-MiniLM-L6-v2` sentence embeddings with K-means cluster centroids
  - Sigmoid-calibrated similarity: `1 / (1 + exp(-10 * (sim - 0.55)))`
  - **84% zero-shot recall** on 10 novel attack categories not seen in training
  - **0% false positive rate** on 20 benign texts
  - Gracefully disabled when `sentence-transformers` is not installed
- **Adversarial CI loop** (`ml/adversarial/`) — automated red-team pipeline
  - `AttackGenerator`: 4 offline mutations — homoglyph Cyrillic, leetspeak, base64, passive rewrite
  - `VariantCurator`: TF-IDF cosine dedup (threshold 0.85), max 3 variants per cluster
  - `HardNegativeMiner`: selects near-misses (score 40–70) for maximum training value
  - CLI: `python scripts/red_team_run.py --n-seeds N --n-variants N [--dry-run] [--offline]`
- **Zero-shot generalization benchmark** (`scripts/zero_shot_benchmark.py`)
  - 10 novel attack categories: sleeper triggers, memory schema manipulation, cross-agent relay, recursive self-modification, cognitive load injection, time-delayed persistence, emotional manipulation, indirect exfiltration, steganographic encoding, voice/persona phishing
  - Gates: recall ≥ 60%, FPR ≤ 10%
  - 61 automated tests in `tests/test_zero_shot_generalization.py`
- **AutoRetrainer quality gate** (`ml/quality_gate.py`) — rejects model if precision < 0.94, recall < 0.94, or P95 latency > 25ms; regression guard (max 2% drop vs baseline)

---

## [0.5.3] — 2026-04-28

### Added
- **REST API server** (`memgar/server.py`) — production-ready FastAPI microservice
  - `POST /analyze` — analyze a single memory entry; returns decision, risk_score, threats, analysis_time_ms
  - `POST /scan` — batch scan up to 100 entries concurrently
  - `GET /health` — uptime, version
  - `GET /ready` — patterns loaded, model loaded, feed available
  - Per-IP rate limiting (default 60 req/min, configurable)
  - Full OpenAPI docs at `/docs`
  - Install: `pip install "memgar[server]"`; run: `uvicorn memgar.server:create_app --factory`
- **12-provider LLM support** (`memgar/llm_analyzer.py`) — `Analyzer(use_llm=True)` works with any supported provider
  - `provider="anthropic"` (default) — Claude claude-sonnet-4-6 / Haiku
  - `provider="openai"` — GPT-4o, GPT-4o-mini, GPT-3.5-Turbo
  - `provider="azure"` — Azure OpenAI Service
  - `provider="google"` — Gemini 1.5 Flash / Pro
  - `provider="mistral"` — Mistral Large / Small
  - `provider="groq"` — LLaMA 3.1 8B/70B (fast inference)
  - `provider="together"` — Together AI open-source models
  - `provider="cohere"` — Command R+
  - `provider="openrouter"` — any OpenRouter model
  - `provider="ollama"` — local models (no API key required)
  - `provider="litellm"` — LiteLLM proxy
  - `provider="openai_compatible"` — any OpenAI-compatible API
  - Automatic failover across providers; prompt caching on Anthropic
- **EU AI Act Compliance Reporter** (`memgar/eu_ai_act.py`, `memgar/compliance.py`)
  - `EUAIActReporter` — tracks requirements per category (transparency, data governance, human oversight, accuracy, robustness, cybersecurity)
  - `EUAIActReport` — full Annex IV technical documentation generator (JSON, Markdown, HTML output)
  - Risk classification: minimal / limited / high / unacceptable
  - Annex IV checklist with pass/fail/partial status per article
  - Gap summary with remediation guidance
- **Behavioral Baseline Engine** (`memgar/behavioral_baseline.py`) — Layer 4
  - EWM baseline per agent on `scan_risk_score` and `scan_block_rate`
  - Deviation levels: NONE / SUSPICIOUS (+15 pts) / CRITICAL (+30 pts)
  - `BaselineRegistry` — process-level singleton keyed by `agent_id`
  - Only amplifies existing threats — never flags `risk_score=0` content
- **Domain-Aware Anomaly Detection** (`memgar/domain_detector.py`)
  - `DomainAnomalyDetector` — detects content that is semantically out-of-scope for an agent's registered domain
  - `AgentDomainProfile` — per-agent domain vocabulary and trust bounds
- **Auto-protect** (`memgar/auto_protect.py`) — `auto_protect()` monkey-patches common memory write paths (dict assignment, list append) to intercept and analyze content automatically

---

## [0.5.2] — 2026-04-06

### Added
- **Denial of Wallet (DoW) Detection** — `memgar.dow` module
  - `DoWDetector` — stateless pattern analysis, 35+ patterns across 7 attack categories
  - `DoWRateLimiter` — sliding-window per-session request/token/cost limiter
  - `DoWSessionMonitor` — budget tracking + velocity spike detection
  - `DoWGuard` — combined defense layer (detection + rate limiting + budget)
  - `create_dow_guard()` — factory with sensible defaults
  - CLI: `memgar dow check`, `memgar dow scan`, `memgar dow budget`
- **DoW attack categories covered:** loop injection, token flooding, tool chain abuse, cost bypass, recursive expansion, parallel fan-out, resource exhaustion

### Fixed
- `__init__.py` — corrected DoW export names (was using old class names)
- `__init__.py` — added missing forensics exports to top-level
- `__all__` — updated to include all v0.5.0–v0.5.2 exports
- `pyproject.toml` — version bump to 0.5.2, improved keywords and classifiers

---

## [0.5.1] — 2026-04-05

### Added
- **Memory Forensics Engine** — `memgar.forensics` module
  - `MemoryForensicsEngine` — deep scan of existing memory stores
  - `ForensicReport` — complete incident report with timeline
  - `ForensicEntry` — per-entry forensic metadata (hash, timestamp, risk)
  - `PoisonEvent` — timeline event with chronological sorting
  - `MemoryCleanser` — in-place cleaning (redact or strip modes)
  - `SkillFileScanner` — scan MEMORY.md, .prompt, .instructions files for backdoors
  - HTML report export with dark-theme UI
  - CLI: `memgar forensics scan`, `memgar forensics skill`, `memgar forensics clean`
- **Supported store formats:** JSON, SQLite, Markdown, plain text, JSONL

---

## [0.5.0] — 2026-04-04

### Added
- **Framework Deep Integrations** — `memgar.frameworks` package
  - **LangChain:** `MemgarSecurityRunnable`, `MemgarChatMemory`, `MemgarConversationBufferMemory`, `SecureVectorStoreRetriever`, `MemgarLCELMiddleware`, `MemgarDocumentFilter`, `create_secure_lcel_chain()`
  - **LlamaIndex:** `MemgarQueryEngineSecurity`, `MemgarIndexSecurity`, `MemgarStorageContextSecurity`, `SecureVectorIndexRetriever`, `MemgarIngestionPipelineSecurity`, `MemgarNodeFilter`, `create_secure_query_pipeline()`
- **High-Performance Core** — `memgar.core` package
  - `AhoCorasick` — O(n) multi-pattern matching
  - `PatternMatcher` — enhanced pattern engine
  - `ThreatScanner` — parallel scanning
- **RAG Poisoning Detection** — LangChain/LlamaIndex deep integration
- **Analyzer enhancements** — `analyze_enhanced()`, `quick_check()` methods
- **Scanner enhancements** — parallel scanning via `ThreadPoolExecutor`

### Fixed
- `ScanResult` field name mismatches resolved
- False positive rate reduced to 0% on 422 test cases

---

## [0.4.0] — 2026-03-30

### Added
- **Multi-Agent Security** — `memgar.agents` package
  - `AgentSecurityGuard`, `AgentMessageValidator`, `TrustChainManager`
  - `DelegationMonitor`, `SwarmDetector`, `MCPSecurityLayer`
- **Multi-Modal Detection** — `memgar.multimodal` package
  - `ImageAnalyzer` — steganography detection
  - `PDFAnalyzer` — PDF threat analysis
  - `AudioAnalyzer` — audio steganography detection

---

## [0.3.9] — 2026-03-29

### Added
- Rebuff benchmark integration
- Unicode NFKC normalization
- Multilingual injection detection (Turkish, Arabic, CJK)
- Smart whitelist (context-aware, domain-specific)

---

## [0.3.8] — 2026-03-28

### Added
- 9 academic paper synthesis (MINJA, AgentPoison, MemoryGraft, InjecMEM, EHR)
- 394 threat patterns (expanded from 255)
- 461 test cases, 100% detection rate

---

## [0.3.7] — 2026-03-24

### Added
- Red team validation (Grade D → A+)
- 422 comprehensive tests, 100% pass rate
- OWASP LLM Top 10 + MITRE ATT&CK compliance (96.4%)

---

## [0.3.0] — 2026-03-22

### Added
- 214 tests, 15 CLI commands
- False positive rate: 0% (down from 47%)
- Layer 2: Sanitization + Provenance
- Layer 3: Trust-Aware Retrieval

---

## [0.2.0] — 2026-03-20

### Added
- 100 threat patterns
- CLI with core commands
- Framework integrations: LangChain, LlamaIndex, CrewAI, AutoGen

---

## [0.1.0] — 2026-03-18

### Added
- Initial MVP: Python CLI, basic pattern matching
- GitHub launch
- Test suite
