"""Regression: Memgar must catch every reproduced, publicly-documented attack.

Each case in simulation.documented_attacks maps to a real, in-the-news
disclosure / CVE (EchoLeak CVE-2025-32711, SpAIware, Morris-II, Slack AI exfil,
Grok crypto hijack, Web3 fake memories, Microsoft recommendation poisoning,
Rules File Backdoor, ASCII smuggling, Bing 'Sydney' leak, Gemini delayed
tool-invocation, DAN). "Caught" = BLOCK or QUARANTINE (not a silent ALLOW).
"""

from __future__ import annotations

import pytest

from memgar import Analyzer, Decision, MemoryEntry
from simulation.documented_attacks import CASES


@pytest.fixture(scope="module")
def analyzer() -> Analyzer:
    return Analyzer(use_llm=False)


@pytest.mark.parametrize("case", CASES, ids=[c.cid for c in CASES])
def test_documented_attack_caught(analyzer: Analyzer, case):
    res = analyzer.analyze(MemoryEntry(content=case.payload, source_type="external",
                                       source_id=case.cid, metadata={"agent_id": case.cid}))
    assert res.decision != Decision.ALLOW, (
        f"{case.cid} ({case.source}) silently allowed: {case.name}")


def test_documented_attacks_mostly_hard_blocked(analyzer: Analyzer):
    blocked = 0
    for case in CASES:
        res = analyzer.analyze(MemoryEntry(content=case.payload, source_type="external",
                                           source_id=case.cid, metadata={"agent_id": case.cid}))
        if res.decision == Decision.BLOCK:
            blocked += 1
    # At least 80% of documented incidents should hard-block, not just quarantine.
    assert blocked / len(CASES) >= 0.80, f"only {blocked}/{len(CASES)} hard-blocked"
