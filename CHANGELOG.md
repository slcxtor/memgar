[CHANGELOG.md](https://github.com/user-attachments/files/26512941/CHANGELOG.md)
# Changelog

All notable changes to Memgar are documented here.

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
