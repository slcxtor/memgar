# Outreach — awesome-list submissions

Maintainer checklist for getting memgar listed in community "awesome" lists.
Low-effort, permanent discoverability. Each is a one-line PR to an external
repo (fork → add the entry → open PR). **These PRs are opened from your own
GitHub account, not from this repo's automation.**

## Canonical description (keep consistent across lists)

Long (when the list allows a full sentence):

> Open-source defense against memory poisoning (OWASP ASI06) for LLM agents —
> write-time pattern + ML + trust-scoring pipeline, 17 framework adapters, and a
> signed threat feed. Runs locally, no API key required.

Short (terse awesome-list style):

> memory-poisoning (OWASP ASI06) defense for LLM agents — write-time scanning,
> trust scoring, signed threat feed; local, no API key.

Keep it honest: no "production-grade"/"enterprise" superlatives, no unaudited
claims. The transparency *is* the pitch.

## Targets

| List | Category to add under | Format | Status |
|------|----------------------|--------|--------|
| [corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) | **Tools** | `*   [Name](url): description` | [ ] submitted |
| [wearetyomsmnv/Awesome-LLM-agent-Security](https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security) | Defenses / Tools (verify) | check README | [ ] submitted |
| [tenable/awesome-llm-cybersecurity-tools](https://github.com/tenable/awesome-llm-cybersecurity-tools) | Defensive / Tools (verify) | check README | [ ] submitted |
| [trailofbits/awesome-ml-security](https://github.com/trailofbits/awesome-ml-security) | Tools / Defenses (verify) | check README | [ ] submitted |
| [punkpeye/awesome-mcp-servers](https://github.com/punkpeye/awesome-mcp-servers) | Security (memgar ships an MCP server) | check README | [ ] submitted |
| [e2b-dev/awesome-ai-agents](https://github.com/e2b-dev/awesome-ai-agents) | Tools / Security (verify) | check README | [ ] submitted |
| OWASP project directory / `agent-memory-guard` | link back as a production impl | n/a — coordinate w/ OWASP | [ ] submitted |

> Always re-read the target list's CONTRIBUTING + existing entries before
> submitting; categories and ordering (often alphabetical) differ per list.

## Ready-to-paste entries

**corca-ai/awesome-llm-security** — under `## Tools` (verified format):

```markdown
*   [Memgar](https://github.com/slcxtor/memgar): open-source defense against memory poisoning (OWASP ASI06) for LLM agents — write-time pattern/ML/trust-scoring pipeline, 17 framework adapters, signed threat feed; local, no API key.
```

**Generic bullet** (adapt the link/desc to each list's house style):

```markdown
- [Memgar](https://github.com/slcxtor/memgar) — memory-poisoning (OWASP ASI06) defense for LLM agents: write-time scanning, trust scoring, signed threat feed; runs locally, no API key.
```

## How to submit one (≈10 min each)

1. Open the target list repo → **Fork**.
2. Edit its `README.md`: add the entry under the right category, matching the
   existing bullet style and (if the section is alphabetical) the right spot.
3. Commit on a branch like `add-memgar`.
4. Open a PR; title e.g. `Add Memgar (OWASP ASI06 memory-poisoning defense)`.
   PR body: one sentence on what it is + the repo link. Be concise; maintainers
   merge clean, on-topic, non-promotional entries fastest.
5. Tick the box in the table above.

## Notes

- Don't mass-submit identical PRs in one burst — space them out; some maintainers
  flag coordinated promo.
- The OWASP `agent-memory-guard` link-back is the highest-credibility one but is
  a conversation, not a drive-by PR — engage via the project's issues/Slack first.
