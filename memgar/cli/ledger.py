"""`memgar ledger` command group — memory integrity ledger."""

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
def ledger() -> None:
    """
    🔐 Memory Integrity Ledger — tamper-evident hash chain.

    Every entry is SHA-256 hashed and chained to the previous one.
    Any modification breaks the chain and is immediately detectable.

    Commands:
        init    Create a new ledger
        append  Add a memory entry
        verify  Verify chain integrity
        status  Show ledger status
        audit   Full audit: tamper check + content threat scan
    """
    pass


@ledger.command("init")
@click.argument("path")
@click.option("--json", "output_json", is_flag=True)
def ledger_init(path, output_json):
    """Create a new memory integrity ledger (.json or .db)."""
    from memgar.memory_ledger import MemoryLedger
    if Path(path).exists():
        console.print(f"[yellow]⚠️  Already exists: {path}[/yellow]"); return
    ledger_obj = MemoryLedger(path=path)
    st = ledger_obj.status()
    if output_json:
        console.print_json(json.dumps(st, indent=2)); return
    console.print()
    console.print(Panel(
        f"[bold green]✅ Ledger created[/bold green]\n\n"
        f"[dim]Path:[/dim]   {path}\n"
        f"[dim]Format:[/dim] {'SQLite' if path.endswith(('.db','.sqlite')) else 'JSON'}",
        title="🔐 Ledger Init", border_style="green"))
    console.print()


@ledger.command("append")
@click.argument("path", type=click.Path(exists=True))
@click.argument("content", required=False)
@click.option("--file", "-f", type=click.Path(exists=True))
@click.option("--source", default="cli")
@click.option("--json", "output_json", is_flag=True)
def ledger_append(path, content, file, source, output_json):
    """Append a memory entry to the ledger."""
    from memgar.memory_ledger import MemoryLedger
    if file: content = Path(file).read_text(encoding="utf-8")
    elif not content: content = click.get_text_stream("stdin").read().strip()
    if not content: console.print("[red]Error: No content[/red]"); raise SystemExit(1)
    ledger_obj = MemoryLedger(path=path)
    eid = ledger_obj.append(content, metadata={"source": source})
    if output_json:
        console.print_json(json.dumps(ledger_obj.get_entry(eid).to_dict(), indent=2)); return
    console.print(f"[green]✅ Appended:[/green] {eid}  [dim](#{len(ledger_obj)-1})[/dim]")


@ledger.command("verify")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True)
@click.option("--stop-at-first", is_flag=True)
def ledger_verify(path, output_json, stop_at_first):
    """
    Verify ledger chain integrity. Exit 0=valid, 2=tampered.

    \b
    Examples:
        memgar ledger verify ./agent.ledger.json
        memgar ledger verify ./agent.ledger.db --json
    """
    from memgar.memory_ledger import MemoryLedger
    ledger_obj = MemoryLedger(path=path)
    with console.status("[bold blue]🔍 Verifying chain...[/bold blue]"):
        report = ledger_obj.verify(stop_at_first=stop_at_first)
    if output_json:
        console.print_json(report.to_json())
        raise SystemExit(0 if report.is_valid else 2)
    color = "green" if report.is_valid else "red"
    console.print()
    console.print(Panel(
        f"[bold {color}]{'✅ VALID — Chain intact' if report.is_valid else '🚨 TAMPERED — Chain broken'}[/bold {color}]\n\n"
        f"[dim]Total:[/dim]    {report.total_entries}\n"
        f"[dim]Valid:[/dim]    [green]{report.valid_count}[/green]\n"
        f"[dim]Tampered:[/dim] [red]{report.tampered_count}[/red]\n"
        f"[dim]Broken:[/dim]   [red]{report.broken_count}[/red]"
        + (f"\n[dim]First breach:[/dim] entry #{report.first_breach_index}" if report.first_breach_index is not None else ""),
        title="🔐 Ledger Integrity", border_style=color))
    if report.tamper_events:
        tbl = Table(box=box.SIMPLE, show_header=True)
        tbl.add_column("#", width=5); tbl.add_column("Type", width=10)
        tbl.add_column("Entry ID", width=20); tbl.add_column("Preview", style="dim")
        for ev in report.tamper_events[:10]:
            c = "red" if ev.tamper_type.value == "tampered" else "orange1"
            tbl.add_row(str(ev.sequence), f"[{c}]{ev.tamper_type.value.upper()}[/{c}]",
                        ev.entry_id[:18], ev.content_preview[:50])
        console.print(tbl)
    console.print()
    raise SystemExit(0 if report.is_valid else 2)


@ledger.command("status")
@click.argument("path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True)
def ledger_status(path, output_json):
    """Show ledger status (no full verification)."""
    from memgar.memory_ledger import MemoryLedger
    st = MemoryLedger(path=path).status()
    if output_json:
        console.print_json(json.dumps(st, indent=2)); return
    console.print()
    console.print(Panel(
        f"[dim]Entries:[/dim]      {st['entry_count']}\n"
        f"[dim]Last updated:[/dim] {st['last_updated'][:19] if st['last_updated'] else 'never'}\n"
        f"[dim]Head hash:[/dim]    {st['head_hash'][:32]}...\n"
        f"[dim]Storage:[/dim]      {st['storage']}",
        title=f"🔐 Ledger — {Path(path).name}", border_style="blue"))
    console.print()


@ledger.command("audit")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None)
@click.option("--json", "output_json", is_flag=True)
def ledger_audit(path, output, output_json):
    """Full audit: tamper detection + content threat scan."""
    from memgar.memory_ledger import LedgerForensicsIntegration
    integration = LedgerForensicsIntegration(ledger_path=path)
    with console.status("[bold blue]🔐 Running full ledger audit...[/bold blue]"):
        report = integration.full_audit()
    if output: Path(output).write_text(json.dumps(report, indent=2))
    if output_json:
        console.print_json(json.dumps(report, indent=2)); return
    s = report["summary"]
    is_clean = s["ledger_valid"] and not s["content_compromised"]
    color = "green" if is_clean else "red"
    console.print()
    console.print(Panel(
        f"[bold {color}]{'✅ CLEAN' if is_clean else '🚨 ISSUES FOUND'}[/bold {color}]\n\n"
        f"[dim]Tamper risk:[/dim]  {s['tamper_risk']}\n"
        f"[dim]Content risk:[/dim] {s['content_risk']}\n"
        f"[dim]Entries:[/dim]      {s['total_entries']}\n"
        f"[dim]Tampered:[/dim]     {s['tampered_entries']}\n"
        f"[dim]Poisoned:[/dim]     {s['poisoned_entries']}",
        title="🔐 Full Ledger Audit", border_style=color))
    console.print()
    raise SystemExit(0 if is_clean else 2)
