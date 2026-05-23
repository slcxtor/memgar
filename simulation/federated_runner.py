"""Run the cross-company federation simulation in two modes.

    python -m simulation.federated_runner

Builds a four-company federation and fires the 2025-2026 cross-company
attack catalogue (``simulation/attacks/federated.py``) at it, once with
naive infrastructure and once with the full Memgar shield. The home
company ``northwind`` is the defender we score.

Outputs:
  * simulation/reports/federated_report.md
  * simulation/reports/federated_scoreboard.json
  * stdout summary
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from .federation import Federation
from .attacks.federated import FED_SCENARIOS, HOME
from .attacks.scenarios import ScenarioResult


REPORTS_DIR = Path(__file__).parent / "reports"

# The federation roster. Order matters only for determinism.
ROSTER = ["northwind", "globex", "vendorco", "shadowtrust"]


def run_one(mode: str, scenario_fn) -> Dict[str, Any]:
    sid = scenario_fn.__name__.replace("fscenario_", "")
    fed = Federation(mode, sid, ROSTER, home_id=HOME)
    try:
        result: ScenarioResult = scenario_fn(fed)
    except Exception as exc:  # keep the run honest — surface, don't hide
        result = ScenarioResult(
            scenario_id="ERR", title=f"{scenario_fn.__name__} raised",
            success_for_attacker=False, evidence={"error": repr(exc)},
            detail=str(exc))
    return {
        "scenario_id": result.scenario_id,
        "title": result.title,
        "mode": mode,
        "attacker_won": result.success_for_attacker,
        "detail": result.detail,
        "evidence": result.evidence,
        "shield_events": _collect_shield_evidence(fed) if mode == "shielded" else {},
    }


def _collect_shield_evidence(fed: Federation) -> Dict[str, Any]:
    home = fed.companies[HOME]
    out: Dict[str, Any] = {}
    out["b2b_blocked"] = home.ctx.coordinator.blocked_messages
    # Memory writes refused across the home org.
    refused: Dict[str, int] = {}
    for name, ag in home.ctx.agents.items():
        events = getattr(ag.memory, "events", None)
        if events:
            n = sum(1 for e in events if not e.get("allowed", True))
            if n:
                refused[name] = n
    out["home_memory_writes_refused"] = refused
    # Shared-resource rejections (multi-tenant blast-radius containment).
    rag = fed.shared_rag
    if rag is not None and hasattr(rag, "rejected"):
        out["shared_rag_rejected"] = [d.doc_id for d in rag.rejected]
        out["shared_rag_quarantined"] = [d.doc_id for d in rag.quarantined]
    tools = fed.shared_tools
    if tools is not None and hasattr(tools, "blocked"):
        out["shared_tool_calls_blocked"] = [
            {"tool": r.tool, "rationale": r.rationale} for r in tools.blocked]
    # Triage perimeter drops on the home company.
    triage = home.ctx.agents.get("triage")
    if triage is not None:
        out["home_triage_drops"] = [a for a in triage.actions
                                    if a.get("kind") in {"drop_email", "swarm_drop"}]
    return out


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    rows: List[Dict[str, Any]] = []
    for fn in FED_SCENARIOS:
        un = run_one("undefended", fn)
        sh = run_one("shielded", fn)
        rows.append({"undefended": un, "shielded": sh})

    sb_path = REPORTS_DIR / "federated_scoreboard.json"
    sb_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path = REPORTS_DIR / "federated_report.md"
    _write_markdown(rows, md_path)
    _print_table(rows)
    print(f"\nMarkdown report:  {md_path}")
    print(f"Full scoreboard:  {sb_path}")
    return 0


def _is_attack(sid: str) -> bool:
    return sid.startswith("F") and not sid.startswith("FC")


def _write_markdown(rows: List[Dict[str, Any]], path: Path) -> None:
    L: List[str] = []
    L.append("# Memgar Cross-Company Federation Simulation — Report")
    L.append("")
    L.append(f"A **four-company federation** ({', '.join(ROSTER)}) sharing a "
             "vendor-portal RAG and an MCP/tool provider, with partial B2B "
             "trust between organisations. The home company **northwind** is "
             "the defender. Each 2025-2026 cross-company attack is fired first "
             "at naive infrastructure, then at the full **Memgar** stack.")
    L.append("")
    attack_rows = [r for r in rows if _is_attack(r["undefended"]["scenario_id"])]
    won_un = sum(int(r["undefended"]["attacker_won"]) for r in attack_rows)
    won_sh = sum(int(r["shielded"]["attacker_won"]) for r in attack_rows)
    total = len(attack_rows)
    L.append("## Headline")
    L.append("")
    L.append(f"- Attacks landed against the **undefended** federation: **{won_un}/{total}**")
    L.append(f"- Attacks landed against the **Memgar-shielded** federation: **{won_sh}/{total}**")
    if total:
        L.append(f"- Net attacks neutralised: **{won_un - won_sh}/{total}** "
                 f"({(won_un - won_sh) / total * 100:.0f} % reduction)")
    ctrl = next((r for r in rows if r["undefended"]["scenario_id"] == "FC1"), None)
    if ctrl:
        L.append(f"- Benign partner control passed shielded run: "
                 f"**{'yes' if not ctrl['shielded']['attacker_won'] else 'NO — FP regression'}**")
    L.append("")
    losses = [r["shielded"] for r in attack_rows if r["shielded"]["attacker_won"]]
    if losses:
        L.append("## Open gaps — attacks that still landed under the shield")
        L.append("")
        for l in losses:
            L.append(f"- **{l['scenario_id']} — {l['title']}**")
            L.append(f"  - {l['detail']}")
        L.append("")
    else:
        L.append("## Open gaps")
        L.append("")
        L.append("None in this run — every cross-company attack was neutralised. "
                 "Read the Honesty notes before drawing conclusions.")
        L.append("")
    L.append("## Per-scenario verdicts")
    L.append("")
    L.append("| ID | Scenario | Undefended | Memgar-shielded | Δ |")
    L.append("|----|----------|-----------:|-----------------:|---|")
    for r in rows:
        un, sh = r["undefended"], r["shielded"]
        if un["scenario_id"] == "FC1":
            un_lbl = "lost" if un["attacker_won"] else "passed"
            sh_lbl = "lost" if sh["attacker_won"] else "passed"
            delta = "(control)"
        else:
            un_lbl = "ATTACK LANDED" if un["attacker_won"] else "blocked"
            sh_lbl = "ATTACK LANDED" if sh["attacker_won"] else "blocked"
            delta = "✓" if (un["attacker_won"] and not sh["attacker_won"]) else (
                    "✗" if (not un["attacker_won"] and sh["attacker_won"]) else "—")
        L.append(f"| {un['scenario_id']} | {un['title']} | {un_lbl} | {sh_lbl} | {delta} |")
    L.append("")
    L.append("## How each attack was caught")
    L.append("")
    for r in rows:
        sh = r["shielded"]
        if sh["scenario_id"] == "FC1":
            continue
        L.append(f"### {sh['scenario_id']} — {sh['title']}")
        L.append("")
        L.append(f"*{sh['detail']}*")
        L.append("")
        ev = sh.get("shield_events", {}) or {}
        if ev.get("b2b_blocked"):
            L.append(f"- **B2B boundary blocks:** {len(ev['b2b_blocked'])} "
                     "cross-company message(s) refused")
        if ev.get("home_memory_writes_refused"):
            parts = [f"{k}: {v}" for k, v in ev["home_memory_writes_refused"].items()]
            L.append("- **Home memory writes refused:** " + "; ".join(parts))
        if ev.get("shared_rag_rejected"):
            L.append(f"- **Shared-portal docs rejected:** {ev['shared_rag_rejected']}")
        if ev.get("shared_rag_quarantined"):
            L.append(f"- **Shared-portal docs quarantined:** {ev['shared_rag_quarantined']}")
        if ev.get("shared_tool_calls_blocked"):
            tools = [t["tool"] for t in ev["shared_tool_calls_blocked"]]
            L.append(f"- **Shared tool calls blocked:** {tools}")
        if ev.get("home_triage_drops"):
            L.append(f"- **Home triage drops:** {len(ev['home_triage_drops'])}")
        L.append("")
        un = r["undefended"]
        L.append("<details><summary>Undefended evidence</summary>\n\n"
                 f"```json\n{json.dumps(un['evidence'], indent=2, default=str)[:1000]}\n```\n\n</details>")
        L.append("")
    L.append("## Honesty notes")
    L.append("")
    L.append("- Layer 2 (LLM semantic analysis) is **disabled**; every block is "
             "Layer 1 patterns + Layer 3 trust + the B2B trust gate + per-component "
             "guards (ShieldedMemoryStore, ShieldedToolRuntime, ShieldedRagIndex).")
    L.append("- The B2B trust gate authenticates partners by the *real* sending "
             "company, never the claimed agent-card identity. Over-trusted but "
             "authenticated partners (F01, F09) still clear the boundary — those "
             "are caught downstream at the memory/tool layer, which is the point.")
    L.append("- Determinism: each company is seeded per (company, scenario); runs "
             "reproduce byte-identically.")
    L.append("")
    L.append("## Reproducing")
    L.append("")
    L.append("```bash\npython -m simulation.federated_runner\n```")
    path.write_text("\n".join(L), encoding="utf-8")


def _print_table(rows: List[Dict[str, Any]]) -> None:
    print()
    print("=" * 96)
    print(f"{'ID':<6}{'Scenario':<52}{'Undefended':>12}{'Shielded':>12}{'Δ':>10}")
    print("-" * 96)
    won_un = won_sh = total = 0
    for row in rows:
        un, sh = row["undefended"], row["shielded"]
        sid = un["scenario_id"]
        if _is_attack(sid):
            un_mark = "ATTACK WON" if un["attacker_won"] else "blocked"
            sh_mark = "ATTACK WON" if sh["attacker_won"] else "blocked"
            won_un += int(un["attacker_won"]); won_sh += int(sh["attacker_won"]); total += 1
            v = "+" if (un["attacker_won"] and not sh["attacker_won"]) else (
                "=" if un["attacker_won"] == sh["attacker_won"] else "-")
        else:
            un_mark = "lost" if un["attacker_won"] else "passed"
            sh_mark = "lost" if sh["attacker_won"] else "passed"
            v = "(ctrl)"
        print(f"{sid:<6}{un['title'][:50]:<52}{un_mark:>12}{sh_mark:>12}{v:>10}")
    print("-" * 96)
    print(f"      Attacker successes:                              {won_un}/{total:<8}  {won_sh}/{total}")
    if total:
        print(f"      Attacks neutralised by Memgar:                   {won_un - won_sh}/{total} "
              f"({(won_un - won_sh) / total * 100:.0f}% reduction)")
    print("=" * 96)


if __name__ == "__main__":
    sys.exit(main())
