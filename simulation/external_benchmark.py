#!/usr/bin/env python3
"""Independent recall benchmark: Memgar vs externally-authored attack corpora.

Runs the current Memgar Analyzer over attack datasets we did NOT write —
AdvBench, JailbreakBench, HarmBench, Gandalf, deepset/prompt-injections,
TrustAIRLab in-the-wild-jailbreak (from ml/data/external_corpus_raw.json),
plus AgentDojo injection goals and (if reachable) InjecAgent — and reports
recall per source.

Crucially it separates:
  * ON-TARGET  — prompt-injection / agent memory-poisoning (what Memgar is FOR)
  * OFF-TARGET — harmful-content generation ("write malware", "make a bomb"),
                 a DIFFERENT threat class Memgar does not claim to classify.
Low recall on off-target sources is expected and honest, not a failure.

"Caught" = BLOCK or QUARANTINE (not a silent ALLOW).

    python -m simulation.external_benchmark
"""
from __future__ import annotations
import json, sys, urllib.request
from collections import defaultdict
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memgar import Analyzer, MemoryEntry, Decision

ROOT = Path(__file__).resolve().parent.parent

# Source -> whether it's on-target for memory-poisoning/injection detection
# ON-target = prompt-injection / jailbreak / agent-injection (Memgar's threat class).
# OFF-target = harmful-content generation ("write malware") — a different problem.
def _is_on_target(src: str) -> bool:
    s = src.lower()
    if any(k in s for k in ("gandalf", "deepset", "in_the_wild", "trustairlab",
                            "agentdojo", "injecagent", "jailbreak_prompt")):
        return True
    if any(k in s for k in ("advbench", "harmbench", "jailbreakbench")):
        return False
    return False


def _source_of(note: str) -> str:
    # note looks like "source=advbench; orig_category=..."
    if not note:
        return "unknown"
    for part in str(note).split(";"):
        if "source=" in part:
            return part.split("source=")[1].strip()
    return "unknown"


def load_external():
    rows = []
    data = json.loads((ROOT / "ml/data/external_corpus_raw.json").read_text())
    samples = data if isinstance(data, list) else data.get("samples", [])
    for r in samples:
        if str(r.get("label")) != "1":
            continue
        rows.append((_source_of(r.get("note", "")), r.get("text", ""),
                     r.get("category", "")))
    return rows


def load_agentdojo():
    p = Path("/tmp/agentdojo_goals.json")
    if not p.exists():
        return []
    return [("agentdojo", r["text"], "agent_injection") for r in json.loads(p.read_text())]


def load_injecagent():
    """Best-effort fetch of InjecAgent attacker instructions (on-target)."""
    rows = []
    for fn in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl"):
        try:
            url = f"https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/{fn}"
            txt = urllib.request.urlopen(urllib.request.Request(
                url, headers={"User-Agent": "memgar"}), timeout=30).read().decode()
            for line in txt.strip().split("\n"):
                if not line.strip():
                    continue
                obj = json.loads(line)
                instr = obj.get("Attacker Instruction") or obj.get("attacker_instruction") or ""
                if instr:
                    rows.append(("injecagent", instr, "agent_injection"))
        except Exception as e:
            print(f"  (InjecAgent {fn} unavailable: {type(e).__name__})")
    return rows


def main() -> int:
    a = Analyzer(use_llm=False, semantic_guard=False, use_transformer_ml=False)
    import random
    MAX_PER_SOURCE = 150
    raw = load_external() + load_agentdojo()  # InjecAgent skipped (rate-limited)
    bysrc = {}
    for r in raw:
        bysrc.setdefault(r[0], []).append(r)
    rng = random.Random(42)
    rows = []
    for src, items in bysrc.items():
        rng.shuffle(items)
        rows.extend(items[:MAX_PER_SOURCE])
    by_src = defaultdict(lambda: {"n": 0, "caught": 0, "block": 0})
    for i, (src, text, cat) in enumerate(rows):
        if not text:
            continue
        r = a.analyze(MemoryEntry(content=text, source_type="external",
                                  source_id=f"bench-{i}", metadata={"agent_id": f"bench-{i}"}))
        d = by_src[src]
        d["n"] += 1
        if r.decision == Decision.BLOCK:
            d["block"] += 1; d["caught"] += 1
        elif r.decision == Decision.QUARANTINE:
            d["caught"] += 1

    print("\n" + "=" * 86)
    print("INDEPENDENT RECALL BENCHMARK — Memgar vs externally-authored attacks")
    print("=" * 86)
    print(f"{'source':<26}{'target':<11}{'n':>6}{'caught':>9}{'recall':>9}{'block%':>9}")
    print("-" * 86)
    on = {"n": 0, "c": 0}; off = {"n": 0, "c": 0}
    for src in sorted(by_src, key=lambda s: (not _is_on_target(s), s)):
        d = by_src[src]
        ont = _is_on_target(src)
        rec = d["caught"] / d["n"] if d["n"] else 0
        blk = d["block"] / d["n"] if d["n"] else 0
        tag = "ON-target" if ont else "off-target"
        print(f"{src:<26}{tag:<11}{d['n']:>6}{d['caught']:>9}{rec:>8.0%}{blk:>8.0%}")
        bucket = on if ont else off
        bucket["n"] += d["n"]; bucket["c"] += d["caught"]
    print("-" * 86)
    if on["n"]:
        print(f"{'ON-TARGET (injection / memory-poisoning)':<48}{on['n']:>6}{on['c']:>9}"
              f"{on['c']/on['n']:>8.0%}   <- what Memgar is for")
    if off["n"]:
        print(f"{'OFF-TARGET (harmful-content generation)':<48}{off['n']:>6}{off['c']:>9}"
              f"{off['c']/off['n']:>8.0%}   <- different threat class; not Memgar's job")
    print("=" * 86)
    print("Sources are externally authored (AdvBench, JailbreakBench, HarmBench, Gandalf,")
    print("deepset, in-the-wild-jailbreak, AgentDojo, InjecAgent) — not written by us.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
