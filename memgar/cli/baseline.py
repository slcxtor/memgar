"""`memgar baseline` command group — behavioral baseline engine."""

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
from memgar.cli import main
from memgar.cli._banner import (
    DECISION_STYLES,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    console,
    print_banner,
)
from memgar.models import Decision, Severity
from memgar.patterns import PATTERNS, pattern_stats
from memgar.scanner import Scanner


@main.group()
def baseline() -> None:
    """
    Behavioral baseline monitoring — detect deviations from learned normal.

    Commands:
        train   Feed observations to build a baseline from a log file
        check   Check current deviation against stored baseline
        status  Show baseline statistics
        report  Print the latest deviation report
        reset   Reset baseline (one signal or all)
    """
    pass


@baseline.command("train")
@click.argument("log_path", type=click.Path(exists=True))
@click.option("--store", default="./memgar_baseline.json", help="Baseline store path")
@click.option("--agent-id", default="default")
@click.option("--alpha", default=0.02, type=float, help="EWM smoothing factor")
@click.option("--json", "output_json", is_flag=True)
def baseline_train(log_path, store, agent_id, alpha, output_json):
    """
    Build baseline from a SIEM JSONL or scan log file.

    Reads each line as a JSON event and feeds relevant signals
    into the baseline engine.

    \b
    Examples:
        memgar baseline train ./siem_events.jsonl
        memgar baseline train ./memgar_audit.json --agent-id agt_abc
    """
    import json as _json

    from memgar.behavioral_baseline import BaselineIntegration, BehavioralBaseline

    bl = BehavioralBaseline(agent_id=agent_id, alpha=alpha)
    hooks = BaselineIntegration(bl)

    count = 0
    errors = 0
    for line in Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = _json.loads(line)
            # Try to extract signals from SIEM OCSF events
            cat = ev.get("memgar_category", ev.get("category", ""))
            if "threat" in cat or "scan" in cat or "protect" in cat:
                hooks.on_scan(
                    risk_score   = ev.get("risk_score", ev.get("finding", {}).get("risk_score", 0)) or 0,
                    decision     = "block" if ev.get("status") == "Blocked" else "allow",
                    threat_count = len(ev.get("unmapped", {}).get("threats", [])),
                )
            elif "token" in cat or "auth" in cat:
                hooks.on_token_event(
                    event        = "issue",
                    scope_denied = "scope" in ev.get("message", "").lower(),
                )
            elif "memory" in cat or "write" in cat:
                hooks.on_memory_write(
                    trust_score  = float(ev.get("trust_score", 0.5)),
                    source_type  = ev.get("source_type", "unknown"),
                    approved     = ev.get("status") != "Blocked",
                )
            count += 1
        except Exception:
            errors += 1

    st = bl.stats()
    if output_json:
        console.print_json(json.dumps({**st, "events_processed": count, "errors": errors}, indent=2))
        return

    console.print()
    console.print(Panel(
        f"[bold green]Training complete[/bold green]\n\n"
        f"[dim]Events:[/dim]   {count}\n"
        f"[dim]Errors:[/dim]   {errors}\n"
        f"[dim]Stable:[/dim]   {st['is_stable']}\n"
        f"[dim]Frozen:[/dim]   {st['frozen']}\n"
        f"[dim]Signals:[/dim]  {st['stable_signals']}/{st['total_signals']}",
        title="Baseline Training", border_style="green"))
    console.print()


@baseline.command("check")
@click.option("--agent-id", default="default")
@click.option("--json", "output_json", is_flag=True)
def baseline_check(agent_id, output_json):
    """
    Check current behavioral state against baseline.

    Prints a deviation report. Exit code reflects severity:
        0 = NORMAL
        1 = ELEVATED or SUSPICIOUS
        2 = CRITICAL
    """
    from memgar.behavioral_baseline import BehavioralBaseline, DeviationLevel

    bl = BehavioralBaseline(agent_id=agent_id)
    report = bl.check()

    if output_json:
        console.print_json(json.dumps(report.to_dict(), indent=2))
        exit_code = {
            DeviationLevel.NORMAL:     0,
            DeviationLevel.ELEVATED:   1,
            DeviationLevel.SUSPICIOUS: 1,
            DeviationLevel.CRITICAL:   2,
        }.get(report.level, 0)
        raise SystemExit(exit_code)

    color = {
        DeviationLevel.NORMAL:     "green",
        DeviationLevel.ELEVATED:   "yellow",
        DeviationLevel.SUSPICIOUS: "orange1",
        DeviationLevel.CRITICAL:   "red",
    }.get(report.level, "white")

    console.print()
    console.print(Panel(
        "[bold " + color + "]" + report.level.value.upper() + "[/bold " + color + "]\n\n"
        "[dim]Score:[/dim]    " + f"{report.composite_score:.2f}\n"
        "[dim]Stable:[/dim]   " + str(report.baseline_stable) + "\n"
        "[dim]Signals:[/dim]  " + str(len(report.deviations)) + " active",
        title=f"Behavioral Check: {agent_id}", border_style=color))

    if report.suspicious_signals:
        console.print()
        for d in sorted(report.suspicious_signals, key=lambda x: x.z_score, reverse=True)[:5]:
            tc = "red" if d.level.value == "critical" else "orange1"
            console.print(
                f"  [{tc}]{d.level.value.upper():<10}[/{tc}] "
                f"{d.signal_name:<28} z={d.z_score:.2f}"
                f"  obs={d.observed:.3f}  mean={d.baseline_mean:.3f}"
            )
    console.print()
    raise SystemExit(0 if report.level == DeviationLevel.NORMAL else
                     2 if report.level == DeviationLevel.CRITICAL else 1)


@baseline.command("status")
@click.option("--agent-id", default="default")
@click.option("--json", "output_json", is_flag=True)
def baseline_status(agent_id, output_json):
    """Show baseline engine statistics."""
    from memgar.behavioral_baseline import BehavioralBaseline

    bl = BehavioralBaseline(agent_id=agent_id)
    st = bl.stats()

    if output_json:
        state = bl.baseline_state()
        console.print_json(json.dumps({**st, "signals": state}, indent=2))
        return

    console.print()
    color = "green" if st["is_stable"] else "yellow"
    console.print(Panel(
        "[dim]Agent:[/dim]          " + agent_id + "\n"
        "[dim]Stable:[/dim]         [" + color + "]" + str(st["is_stable"]) + "[/" + color + "]\n"
        "[dim]Frozen:[/dim]         " + str(st["frozen"]) + "\n"
        "[dim]Stable signals:[/dim] " + str(st["stable_signals"]) + "/" + str(st["total_signals"]) + "\n"
        "[dim]Checks:[/dim]         " + str(st["checks"]) + "\n"
        "[dim]Alerts:[/dim]         " + str(st["alerts"]),
        title="Baseline Status", border_style=color))
    console.print()


@baseline.command("report")
@click.option("--agent-id", default="default")
@click.option("--last", default=1, type=int, help="Show last N reports")
@click.option("--json", "output_json", is_flag=True)
def baseline_report(agent_id, last, output_json):
    """Print latest deviation reports."""
    from memgar.behavioral_baseline import BehavioralBaseline

    bl = BehavioralBaseline(agent_id=agent_id)
    bl.check()
    reports = bl.recent_reports(last)

    if output_json:
        console.print_json(json.dumps([r.to_dict() for r in reports], indent=2))
        return

    console.print()
    for r in reports:
        console.print(r.summary())
    console.print()


@baseline.command("reset")
@click.option("--agent-id", default="default")
@click.option("--signal", default=None, help="Reset one signal (default: all)")
def baseline_reset(agent_id, signal):
    """Reset baseline — all signals or one specific signal."""
    from memgar.behavioral_baseline import BehavioralBaseline

    bl = BehavioralBaseline(agent_id=agent_id)
    bl.reset(signal)
    if signal:
        console.print(f"[yellow]Reset signal:[/yellow] {signal} for agent {agent_id}")
    else:
        console.print(f"[yellow]Full baseline reset[/yellow] for agent {agent_id}")
