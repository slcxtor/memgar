"""`memgar learn` command group — self-learning pattern system."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from memgar.analyzer import Analyzer
from memgar.models import Decision, Severity
from memgar.patterns import PATTERNS, pattern_stats
from memgar.scanner import Scanner

from memgar.cli import main
from memgar.cli._banner import (
    DECISION_STYLES,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    console,
    print_banner,
)


@main.group()
def learn() -> None:
    """
    🧠 Self-learning pattern system (human-supervised).

    Detects attack gaps in production traffic, proposes new patterns,
    and lets you approve/reject them. NO pattern becomes active without
    explicit human approval — safe by design.

    Commands:
        scan    Detect missed attacks in content/logs
        review  List pending candidates for review
        approve Approve a candidate pattern
        reject  Reject a candidate pattern
        status  Show learning stats
        export  Export approved patterns as Python code
    """
    pass


@learn.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--store", default="./memgar_learned.json", help="Learning store path")
@click.option("--json", "output_json", is_flag=True)
def learn_scan(path, store, output_json):
    """
    Scan logs/content for attacks that current patterns miss.

    Proposes PatternCandidates for human review.

    \b
    Examples:
        memgar learn scan ./agent_logs/
        memgar learn scan ./memory.json
    """
    from memgar.learning import PatternLearner

    p = Path(path)
    contents = []

    def _read(fp):
        try:
            raw = fp.read_text(encoding="utf-8", errors="replace")
            if fp.suffix == ".json":
                try:
                    data = json.loads(raw)
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        t = item.get("content", item.get("text", "")) if isinstance(item, dict) else str(item)
                        if t.strip():
                            contents.append(t)
                except Exception:
                    pass
            else:
                for line in raw.splitlines():
                    if line.strip():
                        contents.append(line.strip())
        except Exception:
            pass

    if p.is_file():
        _read(p)
    else:
        for f in sorted(p.rglob("*")):
            if f.is_file() and f.suffix.lower() in (".json", ".txt", ".log", ".md"):
                _read(f)

    learner = PatternLearner(store_path=store)
    with console.status("[bold blue]Scanning for pattern gaps...[/bold blue]"):
        new_candidates = learner.detect_gaps(contents)
    st = learner.stats()

    if output_json:
        out = {"new_candidates": [c.to_dict() for c in new_candidates], "stats": st.to_dict()}
        console.print_json(json.dumps(out, indent=2))
        return

    n = len(new_candidates)
    color = "yellow" if n else "green"
    label = str(n) + " new gap(s) detected — review pending" if n else "No new gaps found"
    body = (
        "[bold " + color + "]" + label + "[/bold " + color + "]\n\n"
        "[dim]Scanned:[/dim]  " + str(len(contents)) + " entries\n"
        "[dim]New:[/dim]      " + str(n) + " candidates proposed\n"
        "[dim]Pending:[/dim]  " + str(st.candidates_pending) + " awaiting review"
    )
    console.print()
    console.print(Panel(body, title="Learning: Gap Detection", border_style=color))

    if new_candidates:
        tbl = Table(box=box.SIMPLE, show_header=True)
        tbl.add_column("ID", width=14)
        tbl.add_column("Name", width=30)
        tbl.add_column("Severity", width=10)
        tbl.add_column("Hits", width=6)
        sc = {"critical": "red bold", "high": "orange1", "medium": "yellow", "low": "green"}
        for c in new_candidates:
            tc = sc.get(c.severity, "white")
            tbl.add_row(
                c.candidate_id[:12],
                c.name[:28],
                "[" + tc + "]" + c.severity.upper() + "[/" + tc + "]",
                str(c.hit_count),
            )
        console.print(tbl)
        console.print("[dim]Run: memgar learn review --store " + store + "[/dim]")
    console.print()


@learn.command("review")
@click.option("--store", default="./memgar_learned.json")
@click.option("--json", "output_json", is_flag=True)
def learn_review(store, output_json):
    """List pending candidates awaiting human review."""
    from memgar.learning import PatternLearner
    learner = PatternLearner(store_path=store)
    pending = learner.pending()

    if output_json:
        console.print_json(json.dumps([c.to_dict() for c in pending], indent=2))
        return

    console.print()
    if not pending:
        console.print(Panel(
            "[green]No pending candidates — all reviewed.[/green]",
            title="Learning: Review Queue", border_style="green"))
        console.print()
        return

    console.print(Panel(
        str(len(pending)) + " candidate(s) pending review",
        title="Learning: Review Queue", border_style="yellow"))

    sc = {"critical": "red bold", "high": "orange1", "medium": "yellow", "low": "green"}
    for c in pending:
        tc = sc.get(c.severity, "white")
        body = (
            "[dim]ID:[/dim]          " + c.candidate_id + "\n"
            "[dim]Severity:[/dim]    [" + tc + "]" + c.severity.upper() + "[/" + tc + "]\n"
            "[dim]Category:[/dim]    " + c.category + "\n"
            "[dim]Description:[/dim] " + c.description + "\n"
            "[dim]Hits:[/dim]        " + str(c.hit_count) + "\n"
            "[dim]Source:[/dim]      " + c.source.value + "\n"
            "[dim]MITRE:[/dim]       " + (c.mitre_id or "-") + "\n"
            "[dim]Keywords:[/dim]    " + ", ".join(c.keywords[:5])
        )
        console.print()
        console.print(Panel(body, title="Candidate: " + c.name, border_style=tc))
        if c.examples:
            console.print("  [dim]Example: " + c.examples[0][:120] + "[/dim]")

    console.print()
    console.print("[dim]Approve: memgar learn approve <ID> --store " + store + "[/dim]")
    console.print("[dim]Reject:  memgar learn reject <ID> --reason 'reason' --store " + store + "[/dim]")
    console.print()


@learn.command("approve")
@click.argument("candidate_id")
@click.option("--store", default="./memgar_learned.json")
@click.option("--reviewer", default="human")
@click.option("--json", "output_json", is_flag=True)
def learn_approve(candidate_id, store, reviewer, output_json):
    """
    Approve a pending pattern candidate.

    \b
    Example:
        memgar learn approve LEARN-A1B2C3D4 --reviewer security-team
    """
    from memgar.learning import PatternLearner
    learner = PatternLearner(store_path=store)
    c = learner.approve(candidate_id, reviewer=reviewer)
    if not c:
        console.print("[red]Candidate not found: " + candidate_id + "[/red]")
        raise SystemExit(1)
    if output_json:
        console.print_json(json.dumps(c.to_dict(), indent=2))
        return
    body = (
        "[bold green]Approved: " + c.name + "[/bold green]\n\n"
        "[dim]ID:[/dim]       " + c.candidate_id + "\n"
        "[dim]Reviewer:[/dim] " + reviewer + "\n"
        "[dim]At:[/dim]       " + (c.reviewed_at or "")[:19]
    )
    console.print()
    console.print(Panel(body, title="Learning: Pattern Approved", border_style="green"))
    console.print()


@learn.command("reject")
@click.argument("candidate_id")
@click.option("--reason", required=True, prompt="Rejection reason")
@click.option("--store", default="./memgar_learned.json")
@click.option("--reviewer", default="human")
def learn_reject(candidate_id, reason, store, reviewer):
    """Reject a pending pattern candidate."""
    from memgar.learning import PatternLearner
    learner = PatternLearner(store_path=store)
    c = learner.reject(candidate_id, reason=reason, reviewer=reviewer)
    if not c:
        console.print("[red]Candidate not found: " + candidate_id + "[/red]")
        raise SystemExit(1)
    console.print("[yellow]Rejected:[/yellow] " + c.name + " — " + reason)


@learn.command("status")
@click.option("--store", default="./memgar_learned.json")
@click.option("--json", "output_json", is_flag=True)
def learn_status(store, output_json):
    """Show learning system statistics."""
    from memgar.learning import PatternLearner
    if not Path(store).exists():
        console.print("[dim]No learning store at " + store + " yet.[/dim]\n")
        return
    learner = PatternLearner(store_path=store)
    st = learner.stats()
    valid, errors = learner.verify_store()
    if output_json:
        d = {**st.to_dict(), "store_valid": valid, "chain_errors": errors}
        console.print_json(json.dumps(d, indent=2))
        return
    color = "green" if st.candidates_pending == 0 else "yellow"
    store_status = "valid" if valid else "TAMPERED (" + str(errors) + " errors)"
    body = (
        "[dim]Proposed:[/dim]  " + str(st.candidates_proposed) + "\n"
        "[dim]Approved:[/dim]  [green]" + str(st.candidates_approved) + "[/green]\n"
        "[dim]Pending:[/dim]   [" + color + "]" + str(st.candidates_pending) + "[/" + color + "]\n"
        "[dim]Rejected:[/dim]  " + str(st.candidates_rejected) + "\n"
        "[dim]FP reports:[/dim]" + str(st.false_positives) + "\n"
        "[dim]Gaps seen:[/dim] " + str(st.gaps_detected) + "\n"
        "[dim]Store:[/dim]     " + store_status
    )
    console.print()
    console.print(Panel(body, title="Learning: Status", border_style="blue"))
    console.print()


@learn.command("export")
@click.option("--store", default="./memgar_learned.json")
@click.option("--output", "-o", default=None, help="Write Python code to file")
@click.option("--json", "output_json", is_flag=True)
def learn_export(store, output, output_json):
    """Export approved patterns as patterns.py Python code."""
    from memgar.learning import PatternLearner
    learner = PatternLearner(store_path=store)
    approved = learner._store.approved()
    if not approved:
        console.print("[yellow]No approved patterns to export.[/yellow]")
        return
    code = learner.export_to_python(output_path=output)
    if output_json:
        console.print_json(json.dumps({
            "approved_count": len(approved),
            "output": output or "stdout",
        }, indent=2))
        return
    if output:
        console.print("[green]Exported " + str(len(approved)) + " patterns to: " + output + "[/green]")
        console.print("[dim]Add this to patterns.py and submit a PR.[/dim]")
    else:
        console.print("[dim]Preview (first 400 chars):[/dim]")
        console.print(code[:400] + "\n...")



# =============================================================================
