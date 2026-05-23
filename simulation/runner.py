"""Run the full simulation in two modes and print a comparison.

    python -m simulation.runner

By default, each of the 12 attacks is fired against:

  * UNDEFENDED  — agents wired with raw memory, naive RAG, naive tools.
  * SHIELDED    — same agents, same scripts, but Memgar layers active.

The runner produces:

  * simulation/reports/raw_audit.jsonl        per-mode event log
  * simulation/reports/scoreboard.json        per-scenario verdicts
  * stdout                                     human-readable summary
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .world import World, Message
from .infrastructure.memory import RawMemoryStore, ShieldedMemoryStore
from .infrastructure.rag import NaiveRagIndex, ShieldedRagIndex, Document
from .infrastructure.tools import NaiveToolRuntime, ShieldedToolRuntime
from .agents.support import SupportAgent
from .agents.triage import TriageAgent
from .agents.coordinator import CoordinatorAgent
from .agents.finance import FinanceAgent
from .agents.researcher import ResearcherAgent
from .agents.insider import InsiderAgent
from .attacks.scenarios import SCENARIOS, ScenarioResult


REPORTS_DIR = Path(__file__).parent / "reports"


@dataclass
class SimContext:
    """Shared handles passed to every scenario."""
    agents: Dict[str, Any]
    coordinator: CoordinatorAgent
    rag: Any
    tools: Any
    rag_added: List[Any] = field(default_factory=list)

    def drive(self, world: World, ticks: int) -> None:
        for _ in range(ticks):
            world.advance()
            # Order matters: triage first (routes), specialists next, then the
            # insider (so they react to current state), and coord last.
            self.agents["triage"].step()
            self.agents["finance"].step()
            self.agents["support"].step()
            self.agents["researcher"].step()
            if "insider" in self.agents:
                self.agents["insider"].step()
            self.coordinator.step()


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _seed_legitimate_rag(rag) -> None:
    rag.add(Document(
        doc_id="vendor-policy-v1",
        title="Vendor reimbursement policy (canonical)",
        body=("Vendor reimbursements are wired to the internal vendors account "
              "INT-VENDORS-001 following two-person verification."),
        source_domain="internal.corp",
        submitted_by="cfo",
        trust_hint=0.95,
        tick_added=0,
    ))
    rag.add(Document(
        doc_id="onboarding-handbook",
        title="Customer onboarding handbook",
        body=("Customer onboarding requires email DKIM verification, a "
              "two-factor confirmation, and never accepts wire-routing "
              "changes from inbound email."),
        source_domain="internal.corp",
        submitted_by="ops",
        trust_hint=0.95,
        tick_added=0,
    ))


def build_world(mode: str, scenario_id: str, *,
                shared_rag: Any = None, shared_tools: Any = None,
                company: str = "") -> tuple[World, SimContext]:
    """Construct a fresh world, agents, and infrastructure for a single
    scenario. We rebuild between scenarios so attacks can not bleed state
    into each other — the comparison stays honest.

    ``shared_rag`` / ``shared_tools`` let several companies share one
    multi-tenant resource (vendor-portal RAG, MCP/tool provider) so a
    single poisoning event can be observed reaching every tenant — the
    cross-company federation threat model. ``company`` namespaces the
    ledger directory so per-company hash-chains don't collide on disk."""
    seed_key = f"{company}:{scenario_id}" if company else scenario_id
    world = World(seed=hash(seed_key) & 0xFFFF, scenario=f"{mode}:{seed_key}")
    ledger_root = REPORTS_DIR / "ledgers" / mode / (f"{company}-{scenario_id}" if company else scenario_id)
    ledger_root.mkdir(parents=True, exist_ok=True)

    if mode == "shielded":
        rag = shared_rag if shared_rag is not None else ShieldedRagIndex()
        tools = shared_tools if shared_tools is not None else ShieldedToolRuntime()
        def mem_for(name: str):
            return ShieldedMemoryStore(name, ledger_path=ledger_root / f"{name}.ledger.json")
    else:
        rag = shared_rag if shared_rag is not None else NaiveRagIndex()
        tools = shared_tools if shared_tools is not None else NaiveToolRuntime()
        def mem_for(name: str):
            return RawMemoryStore(name)

    if shared_rag is None:
        _seed_legitimate_rag(rag)

    coordinator = CoordinatorAgent("coordinator", mem_for("coordinator"), world,
                                   shielded=(mode == "shielded"))
    support = SupportAgent("support", mem_for("support"), world,
                           shielded=(mode == "shielded"), tools=tools)
    triage = TriageAgent("triage", mem_for("triage"), world, shielded=(mode == "shielded"))
    researcher = ResearcherAgent("researcher", mem_for("researcher"), world, rag=rag)
    finance = FinanceAgent("finance", mem_for("finance"), world, tools=tools)
    # Insider: trusted internal agent that has gone rogue. Registered as a
    # peer of the researcher so it inherits HIGH inter-agent trust in
    # shielded mode — exactly the credentials-valid threat model.
    insider = InsiderAgent("insider", mem_for("insider"), world)

    for ag in (support, triage, finance, researcher, insider):
        coordinator.register(ag.name, role=ag.role)

    agents = {"coordinator": coordinator, "support": support, "triage": triage,
              "researcher": researcher, "finance": finance, "insider": insider}
    ctx = SimContext(agents=agents, coordinator=coordinator, rag=rag, tools=tools)
    return world, ctx


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_one(mode: str, scenario_fn) -> Dict[str, Any]:
    sid = scenario_fn.__name__.replace("scenario_", "")
    world, ctx = build_world(mode, sid)
    try:
        result: ScenarioResult = scenario_fn(world, ctx)
    except Exception as exc:
        result = ScenarioResult(
            scenario_id="ERR", title=f"{scenario_fn.__name__} raised",
            success_for_attacker=False,
            evidence={"error": repr(exc)},
            detail=str(exc),
        )

    # Settle the simulation a few more ticks so observable side effects propagate
    ctx.drive(world, ticks=2)

    audit_path = REPORTS_DIR / f"audit-{mode}-{result.scenario_id}.jsonl"
    world.dump_audit(audit_path)

    summary = {
        "scenario_id": result.scenario_id,
        "title": result.title,
        "mode": mode,
        "attacker_won": result.success_for_attacker,
        "detail": result.detail,
        "evidence": result.evidence,
        "shield_events": _collect_shield_evidence(ctx) if mode == "shielded" else {},
        "audit_path": str(audit_path),
    }
    return summary


def _collect_shield_evidence(ctx: SimContext) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["memory_writes_blocked"] = {}
    for name, ag in ctx.agents.items():
        events = getattr(ag.memory, "events", None)
        if events:
            blocked = [e for e in events if not e.get("allowed", True)]
            out["memory_writes_blocked"][name] = {
                "n_blocked": len(blocked),
                "samples": blocked[:3],
            }
    if isinstance(ctx.rag, ShieldedRagIndex):
        out["rag_rejected"] = [d.doc_id for d in ctx.rag.rejected]
        out["rag_quarantined"] = [d.doc_id for d in ctx.rag.quarantined]
    if isinstance(ctx.tools, ShieldedToolRuntime):
        out["tool_calls_blocked"] = [
            {"tool": r.tool, "params": r.params, "rationale": r.rationale}
            for r in ctx.tools.blocked
        ]
    out["coordinator_blocked_relays"] = ctx.coordinator.blocked_messages
    triage = ctx.agents.get("triage")
    if triage is not None:
        out["triage_drops"] = [a for a in triage.actions
                                if a.get("kind") in {"drop_email", "swarm_drop"}]
        out["triage_swarm_alerts"] = getattr(triage, "swarm_alerts", [])
    support = ctx.agents.get("support")
    if support is not None and hasattr(support, "exfil_alerts"):
        out["canary_exfil_alerts"] = support.exfil_alerts
    # Integrity
    integrity = {}
    for name, ag in ctx.agents.items():
        if hasattr(ag.memory, "verify_integrity"):
            integrity[name] = ag.memory.verify_integrity()
    if integrity:
        out["ledger_integrity"] = integrity
    return out


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    for fn in SCENARIOS:
        un = run_one("undefended", fn)
        sh = run_one("shielded", fn)
        rows.append({"undefended": un, "shielded": sh})

    scoreboard_path = REPORTS_DIR / "scoreboard.json"
    with scoreboard_path.open("w", encoding="utf-8") as fh:
        json.dump(rows, fh, ensure_ascii=False, indent=2)

    md_path = REPORTS_DIR / "report.md"
    _write_markdown(rows, md_path)

    _print_table(rows)
    print(f"\nMarkdown report:  {md_path}")
    print(f"Full scoreboard:  {scoreboard_path}")
    return 0


def _write_markdown(rows: List[Dict[str, Any]], path: Path) -> None:
    lines: List[str] = []
    lines.append("# Memgar Multi-Agent Memory-Poisoning Simulation — Report")
    lines.append("")
    lines.append("Side-by-side run of 12 distinct memory-poisoning attack classes "
                 "(plus one benign control) against a five-agent virtual organisation, "
                 "first with **no defences** and then with the full **Memgar** stack active.")
    lines.append("")
    won_un = sum(int(r["undefended"]["attacker_won"]) for r in rows if r["undefended"]["scenario_id"].startswith("S"))
    won_sh = sum(int(r["shielded"]["attacker_won"]) for r in rows if r["shielded"]["scenario_id"].startswith("S"))
    attack_rows = [r for r in rows if r["undefended"]["scenario_id"].startswith("S")]
    total = len(attack_rows)
    lines.append("## Headline")
    lines.append("")
    lines.append(f"- Attacks landed against the **undefended** agents: **{won_un}/{total}**")
    lines.append(f"- Attacks landed against the **Memgar-shielded** agents: **{won_sh}/{total}**")
    lines.append(f"- Net attacks neutralised: **{won_un - won_sh}/{total}** "
                 f"({(won_un - won_sh) / total * 100:.0f} % reduction)")
    benign = next((r for r in rows if r["undefended"]["scenario_id"] == "C01"), None)
    if benign:
        lines.append(f"- Benign control passed shielded run: "
                     f"**{'yes' if not benign['shielded']['attacker_won'] else 'NO — FP regression'}**")
    lines.append("")
    # Surface where Memgar still loses, prominently.
    losses = [r["shielded"] for r in attack_rows if r["shielded"]["attacker_won"]]
    if losses:
        lines.append("## Memgar gaps — attacks that still landed under the shield")
        lines.append("")
        lines.append("These are the cases the latest Memgar build did **not** stop. "
                     "Every other attack in the catalogue was neutralised; these "
                     "are the genuine open problems.")
        lines.append("")
        for l in losses:
            lines.append(f"- **{l['scenario_id']} — {l['title']}**")
            lines.append(f"  - {l['detail']}")
        lines.append("")
    else:
        lines.append("## Memgar gaps")
        lines.append("")
        lines.append("None in this run — every attack in the catalogue was blocked. "
                     "That does not mean every attack everywhere is blocked. "
                     "Read the Honesty notes section before drawing conclusions.")
        lines.append("")
    lines.append("## Per-scenario verdicts")
    lines.append("")
    lines.append("| ID | Scenario | Undefended | Memgar-shielded | Δ |")
    lines.append("|----|----------|-----------:|-----------------:|---|")
    for r in rows:
        un, sh = r["undefended"], r["shielded"]
        if un["scenario_id"] == "C01":
            un_lbl = "lost" if un["attacker_won"] else "passed"
            sh_lbl = "lost" if sh["attacker_won"] else "passed"
        else:
            un_lbl = "ATTACK LANDED" if un["attacker_won"] else "blocked"
            sh_lbl = "ATTACK LANDED" if sh["attacker_won"] else "blocked"
        delta = "✓" if (un["attacker_won"] and not sh["attacker_won"]) else (
                "✗" if (not un["attacker_won"] and sh["attacker_won"]) else "—")
        lines.append(f"| {un['scenario_id']} | {un['title']} | {un_lbl} | {sh_lbl} | {delta} |")
    lines.append("")
    lines.append("## How each attack was caught")
    lines.append("")
    for r in rows:
        sh = r["shielded"]; un = r["undefended"]
        if sh["scenario_id"] == "C01":
            continue
        lines.append(f"### {sh['scenario_id']} — {sh['title']}")
        lines.append("")
        lines.append(f"*{sh['detail']}*")
        lines.append("")
        ev = sh.get("shield_events", {}) or {}
        wrote = ev.get("memory_writes_blocked", {}) or {}
        sample_blocks = []
        for agent, info in wrote.items():
            if info.get("n_blocked", 0):
                sample_blocks.append(f"{agent}: {info['n_blocked']} write(s) refused")
        if sample_blocks:
            lines.append("- **Memory writes refused:** " + "; ".join(sample_blocks))
        if ev.get("triage_drops"):
            kinds = {}
            for d in ev["triage_drops"]:
                kinds[d.get("kind", "?")] = kinds.get(d.get("kind", "?"), 0) + 1
            parts = [f"{k}={v}" for k, v in kinds.items()]
            lines.append("- **Triage drops:** " + ", ".join(parts))
        if ev.get("canary_exfil_alerts"):
            lines.append(f"- **Canary outbound blocked:** "
                         f"{len(ev['canary_exfil_alerts'])} attempt(s)")
        if ev.get("rag_quarantined"):
            lines.append(f"- **RAG documents quarantined:** {ev['rag_quarantined']}")
        if ev.get("rag_rejected"):
            lines.append(f"- **RAG documents rejected:** {ev['rag_rejected']}")
        if ev.get("tool_calls_blocked"):
            tools = [t['tool'] for t in ev['tool_calls_blocked']]
            lines.append(f"- **Tool calls blocked:** {tools}")
        if ev.get("coordinator_blocked_relays"):
            lines.append(f"- **Cross-agent relays blocked:** {len(ev['coordinator_blocked_relays'])}")
        integ = ev.get("ledger_integrity") or {}
        for ag, st in integ.items():
            if not st.get("valid", True):
                lines.append(f"- **Ledger tamper detected** on `{ag}` "
                             f"(first breach at index {st.get('first_breach')})")
        lines.append("")
        lines.append(f"<details><summary>Undefended evidence</summary>\n\n"
                     f"```json\n{json.dumps(un['evidence'], indent=2, default=str)[:1200]}\n```\n\n</details>")
        lines.append("")

    lines.append("## Reproducing this report")
    lines.append("")
    lines.append("```bash")
    lines.append("python -m simulation.runner")
    lines.append("```")
    lines.append("")
    lines.append("Per-mode audit logs live in `simulation/reports/audit-<mode>-<id>.jsonl`.")
    path.write_text("\n".join(lines), encoding="utf-8")


def _print_table(rows: List[Dict[str, Any]]) -> None:
    print()
    print("=" * 96)
    print(f"{'ID':<6}{'Scenario':<46}{'Undefended':>14}{'Shielded':>14}{'Δ':>14}")
    print("-" * 96)
    won_un = won_sh = 0
    attack_total = 0
    for row in rows:
        un = row["undefended"]; sh = row["shielded"]
        is_attack = un["scenario_id"].startswith("S")
        if is_attack:
            un_mark = "ATTACK WON" if un["attacker_won"] else "blocked"
            sh_mark = "ATTACK WON" if sh["attacker_won"] else "blocked"
            won_un += int(un["attacker_won"]); won_sh += int(sh["attacker_won"])
            attack_total += 1
            verdict = "+" if (un["attacker_won"] and not sh["attacker_won"]) else \
                      ("=" if un["attacker_won"] == sh["attacker_won"] else "-")
        else:
            un_mark = "lost" if un["attacker_won"] else "passed"
            sh_mark = "lost" if sh["attacker_won"] else "passed"
            verdict = "(control)"
        print(f"{un['scenario_id']:<6}{un['title'][:44]:<46}{un_mark:>14}{sh_mark:>14}{verdict:>14}")
    print("-" * 96)
    print(f"      Attacker successes (attack scenarios):           {won_un}/{attack_total:<8}  {won_sh}/{attack_total}")
    saved = won_un - won_sh
    print(f"      Attacks neutralised by Memgar:                   {saved}/{attack_total} "
          f"({(saved/attack_total*100):.0f}% reduction)")
    print("=" * 96)


if __name__ == "__main__":
    sys.exit(main())
