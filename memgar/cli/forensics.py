"""`memgar forensics` command group — memory forensics / incident response."""

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
def forensics() -> None:
    """
    🔬 Memory forensics — incident response for poisoned memory stores.

    Scan existing memory stores for threats, reconstruct the poisoning
    timeline, and clean infected entries.

    Commands:
        scan   Deep scan a memory store (file or directory)
        skill  Scan a skill/plugin directory for backdoors
        clean  Write a cleaned copy of a poisoned JSON store
    """
    pass


@forensics.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--clean", is_flag=True, help="Generate cleaned versions of poisoned entries")
@click.option("--output", "-o", default=None, help="Save report to file (.html or .json)")
@click.option("--since", default=None, help="Only report entries after this date (ISO: 2026-03-01)")
@click.option("--no-recursive", is_flag=True, help="Do not scan subdirectories")
@click.option("--json", "output_json", is_flag=True, help="Print JSON report to stdout")
@click.option("--min-severity", type=click.Choice(["low", "medium", "high", "critical"]),
              default="medium", help="Minimum severity to flag (default: medium)")
def forensics_scan(path, clean, output, since, no_recursive, output_json, min_severity):
    """
    Deep forensic scan of a memory store.

    \b
    Examples:
        memgar forensics scan ./memory_store/
        memgar forensics scan ./agent_memory.json --clean --output report.html
        memgar forensics scan ./memories/ --since 2026-03-01 --min-severity high
    """
    from memgar.forensics import MemoryForensicsEngine, PoisonSeverity
    sev_map = {"low": PoisonSeverity.LOW, "medium": PoisonSeverity.MEDIUM,
               "high": PoisonSeverity.HIGH, "critical": PoisonSeverity.CRITICAL}
    engine = MemoryForensicsEngine(min_severity=sev_map[min_severity])
    console.print()
    with console.status("[bold blue]🔬 Running forensic scan...[/bold blue]"):
        try:
            report = engine.scan(path=path, clean=clean, since=since, recursive=not no_recursive)
        except FileNotFoundError as e:
            console.print(f"[red]Error: {e}[/red]"); raise SystemExit(1)
    if output_json:
        console.print_json(report.to_json()); raise SystemExit(0 if not report.is_compromised else 2)
    status_color = "red" if report.is_compromised else "green"
    console.print(Panel(
        f"[bold {status_color}]{'🚨 COMPROMISED' if report.is_compromised else '✅ CLEAN'}[/bold {status_color}]\n\n"
        f"[dim]Total:[/dim]    {report.total_entries}\n"
        f"[dim]Poisoned:[/dim] [red]{report.poisoned_entries}[/red]\n"
        f"[dim]Critical:[/dim] [red]{report.critical_count}[/red]  "
        f"[dim]High:[/dim] [orange1]{report.high_count}[/orange1]",
        title="🔬 Forensic Scan", border_style=status_color))
    if report.recommendations:
        for rec in report.recommendations[:5]:
            console.print(f"  {rec}")
    if output:
        engine.export_report(report, output)
        console.print(f"\n[green]Report saved:[/green] {output}")
    console.print()
    raise SystemExit(2 if report.is_compromised else 0)


@forensics.command("skill")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None)
@click.option("--json", "output_json", is_flag=True)
def forensics_skill(path, output, output_json):
    """Scan a skill/plugin directory for backdoors (MEMORY.md, .prompt files)."""
    from memgar.forensics import MemoryForensicsEngine
    engine = MemoryForensicsEngine()
    with console.status("[bold blue]🔬 Scanning skill files...[/bold blue]"):
        report = engine.scan_skill(path)
    if output_json:
        console.print_json(report.to_json()); raise SystemExit(2 if report.is_compromised else 0)
    color = "red" if report.is_compromised else "green"
    console.print(Panel(
        f"[bold {color}]{'🚨 BACKDOOR FOUND' if report.is_compromised else '✅ CLEAN'}[/bold {color}]\n\n"
        f"[dim]Entries scanned:[/dim] {report.total_entries}\n"
        f"[dim]Poisoned:[/dim]        [red]{report.poisoned_entries}[/red]",
        title=f"🔬 Skill Scan — {Path(path).name}", border_style=color))
    if output:
        engine.export_report(report, output)
    console.print()
    raise SystemExit(2 if report.is_compromised else 0)


@forensics.command("clean")
@click.argument("input_path", type=click.Path(exists=True))
@click.argument("output_path")
@click.option("--mode", type=click.Choice(["redact", "strip"]), default="redact")
def forensics_clean(input_path, output_path, mode):
    """Write a sanitized copy of a JSON memory store."""
    from memgar.forensics import MemoryForensicsEngine
    engine = MemoryForensicsEngine(clean_mode=mode)
    with console.status("[bold blue]🧹 Scanning and cleaning...[/bold blue]"):
        report = engine.scan(input_path, clean=True)
        written = engine.write_clean_store(report, output_path)
    console.print(Panel(
        f"[dim]Input:[/dim]   {input_path}\n"
        f"[dim]Output:[/dim]  {output_path}\n"
        f"[dim]Poisoned:[/dim]  [red]{report.poisoned_entries}[/red]  "
        f"[dim]Written:[/dim] [green]{written}[/green]",
        title="🧹 Clean Complete", border_style="green"))
