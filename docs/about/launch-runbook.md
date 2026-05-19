# v1.0 Launch Runbook

Step-by-step plan to take memgar from "code on a branch" to "stable
PyPI release + signed feed live + public announcement." Targets the
maintainer (slcxtor); not user-facing.

## Pre-flight checklist

The launch-prep PR (#NN — this one) ships:

- [x] `pyproject.toml` version `0.5.6 → 1.0.0`
- [x] `pyproject.toml` classifier `Development Status :: 4 - Beta → 5 - Production/Stable`
- [x] `CHANGELOG.md` v1.0.0 entry consolidating Tier 1-3 + integrations + cloud foundation
- [x] `README.md` honest-baseline table (gold + expanded corpus side-by-side, pre-1.0 caveat)
- [x] `similarity_layer.py` threshold calibration (kills SIM-001 false positive)
- [x] `examples/quickstart.py` — 60-second end-to-end demo
- [x] This runbook

The launch-prep PR does NOT publish PyPI or create the v1.0.0 git tag —
those are explicit operator actions below.

## Phase 1 — Repository state (10 minutes)

1. **Merge the launch-prep PR**
   ```bash
   # in this PR's web UI: Squash and merge
   ```
2. **Merge the feed key rotation PR (#63) if not already**
   ```bash
   # ensures feeds/memgar-feed.json.gz reflects 807 patterns
   ```
3. **Close stale PRs that won't make it into v1.0**
   - #32 (`feat(enforcement)`) — 11 days old, big diff, likely conflicts → close with comment "deferred to v1.1, see roadmap"
   - #35 (`docs: polish README quickstart`) — superseded by the launch-prep PR — close
   - #51 (`fix feed loader network failure fallback`) — small, decide on merits → merge or close

## Phase 2 — Threat feed live (5 minutes)

1. **Set the Ed25519 private-key secret**
   ```bash
   # The base64-encoded PEM is in your password manager (entry from
   # 2026-05-19 — `memgar feed signing key (Ed25519) — rotated`)
   echo '<paste base64 PEM here>' | gh secret set MEMGAR_FEED_PRIVATE_KEY_PEM \
       --repo slcxtor/memgar
   ```
2. **Trigger the first real feed release**
   ```bash
   gh workflow run feed-publish.yml \
       -f version_bump=patch \
       --repo slcxtor/memgar
   ```
3. **Verify (after ~2 min)**
   ```bash
   gh release view feed-v1.0.2 --repo slcxtor/memgar
   # Asset: memgar-feed.json.gz (~165 KB)
   ```
4. **Verify client side**
   ```bash
   pip install -U memgar
   memgar feed sync
   memgar feed status
   # → feed_version=1.0.2  pattern_count=807  signed=True
   ```

## Phase 3 — PyPI publish (5 minutes)

The `.github/workflows/publish.yml` (or equivalent — confirm the actual
filename) is wired for trusted publishing. Tag triggers it.

1. **Tag v1.0.0**
   ```bash
   git checkout main
   git pull
   git tag -a v1.0.0 -m "memgar v1.0.0 — first stable release"
   git push origin v1.0.0
   ```
2. **Watch the workflow**
   ```bash
   gh run watch --repo slcxtor/memgar
   ```
3. **Verify on PyPI**
   ```bash
   pip install memgar==1.0.0
   memgar version
   # → memgar 1.0.0
   ```

## Phase 4 — GitHub Release (3 minutes)

1. **Create the release notes**
   - GitHub UI → Releases → "Draft a new release"
   - Tag: `v1.0.0` (already exists from Phase 3)
   - Title: `memgar v1.0.0 — first stable release`
   - Body: paste from CHANGELOG.md v1.0.0 section
   - Attach: a copy of `feeds/memgar-feed.json.gz` (optional convenience)
   - Mark as the latest release

## Phase 5 — Announcement (variable)

This is the bit that's all signal-noise tradeoff. Honest framing is the
biggest predictor of how the post lands.

### Channels in order of leverage

1. **r/LLMDevs** — small, technical, very memgar-adjacent
2. **r/MachineLearning** — high reach, low memgar-relevance; expect skepticism
3. **Hacker News** — high reach, high pickiness; "Show HN" is the right framing
4. **AI safety mailing lists** (LessWrong, MITRE working groups) — slow but high-signal
5. **Twitter/X** — quick, low-bar; thread format with concrete examples
6. **OWASP ASI slack** (if exists) — directly relevant audience
7. **A few cold emails** to AI agent teams you know — explicit "design partner" framing

### Suggested copy (one example, adapt freely)

**Title (HN / r/LLMDevs):**
> Show HN: Memgar — open-source memory poisoning defense for AI agents (Pre-1.0 → 1.0)

**Body opener:**
> Memgar is an open-source library for detecting and blocking memory
> poisoning in AI agents — the class of attacks where a poisoned RAG
> chunk, conversation message, or tool result quietly influences every
> future read.
>
> We just shipped v1.0. The honest summary:
> - 807 patterns covering 7 phases of a memory-poisoning kill chain
> - 4-layer detection (pattern + semantic + LLM + behavioral baseline)
> - Drop-in security wrappers for Mem0, Letta, Pinecone, Chroma, Qdrant,
>   Weaviate, LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI Assistants, MCP
> - Ed25519-signed weekly threat feed with automated MITRE/CVE/OWASP sync
> - Two-corpus calibration: ~80% recall / ~9% FPR on our hand-curated
>   **gold** corpus (95 + 49), ~79% recall / ~36% FPR on the larger
>   **expanded** corpus (gold + mined + augmented = 464 samples). The
>   expanded set is intentionally harder and tracks broader drift.
>   No public benchmark for memory poisoning exists yet — treat any
>   vendor's number as preliminary, ours included.
>
> Not production-tested at scale. Looking for design partners.

The "not production-tested" line is what makes the rest believable. Don't
skip it.

### Don't do

- Don't claim "battle-tested" or "enterprise-ready"
- Don't use "industry-leading" or "best-in-class"
- Don't claim a specific customer unless you have their written go-ahead
- Don't quote precise FPR numbers without the corpus caveat in the same
  breath

## Phase 6 — Post-launch (week 1)

- [ ] Watch issues + DMs daily for the first week
- [ ] Each "won't install" or "false positive on my data" report becomes
      a curated GitHub issue with `triage` label
- [ ] Patch obvious wins fast (small versions: 1.0.1 / 1.0.2)
- [ ] Open one blog post 7-10 days in: "What we learned from 100
      issues" — early honesty signals
- [ ] If 3+ people ask for the same integration / feature, prioritise it
      for 1.1

## Rollback paths

| Problem | Action |
|---|---|
| v1.0.0 has a critical bug | `pip install memgar==0.5.6` is still on PyPI; yank 1.0.0 via `pypi-yank` |
| Feed signed with wrong key | Roll back `verifier.py` to old key constant, push 1.0.1 |
| HN front-page traffic crushes infra | docs.memgar.com is static — no infra to crush. PyPI handles its own load |
| Embarrassing tweet from someone | Don't engage publicly; fix the underlying issue, ship 1.0.1, link to the fix |

## What 1.1 should bring (already in the roadmap)

- Cloud control plane (currently on the `claude/cloud-saas-foundation`
  branch — revive when there's a customer asking)
- Production-grade transformer model (training data + ONNX artifact)
- arXiv paper monitor (LLM-assisted pattern extraction)
- Community submission portal
- Postgres adapter for cloud TenantStore
- WebSocket telemetry streaming
- SOC 2 controls
