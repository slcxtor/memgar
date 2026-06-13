"""`memgar protect` command group — auto-protect runtime."""

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
def protect() -> None:
    """
    🛡️ Auto-protect — zero-config automatic protection.

    Patches all installed AI frameworks (OpenAI, Anthropic, LangChain,
    LlamaIndex) automatically.

    Commands:
        on      Activate auto-protect
        off     Deactivate auto-protect
        status  Show current protection status
    """
    pass


@protect.command("on")
@click.option("--no-block", is_flag=True, help="Log but do not block (monitor mode)")
@click.option("--json", "output_json", is_flag=True)
def protect_on(no_block, output_json):
    """
    Activate auto-protect system-wide.

    \b
    Examples:
        memgar protect on
        memgar protect on --no-block
    """
    from memgar.auto_protect import auto_protect
    status = auto_protect(block_on_threat=not no_block, log_threats=True)
    if output_json:
        console.print_json(json.dumps(status.to_dict(), indent=2)); return
    console.print()
    console.print(Panel(
        f"[bold green]🛡️ Auto-Protect ACTIVE[/bold green]\n\n"
        f"[dim]Block threats:[/dim]  {'Yes' if not no_block else 'No (monitor)'}\n"
        f"[dim]Patched:[/dim]       {', '.join(status.patched_frameworks) or 'waiting for imports'}",
        title="🛡️ Memgar Auto-Protect", border_style="green"))
    console.print()


@protect.command("status")
@click.option("--json", "output_json", is_flag=True)
def protect_status(output_json):
    """Show current auto-protect status."""
    from memgar.auto_protect import get_status
    s = get_status()
    if output_json:
        console.print_json(json.dumps(s.to_dict(), indent=2)); return
    color = "green" if s.active else "red"
    console.print()
    console.print(Panel(
        f"[bold {color}]{'ACTIVE' if s.active else 'INACTIVE'}[/bold {color}]\n\n"
        f"[dim]Patched:[/dim]  {', '.join(s.patched_frameworks) or 'none'}\n"
        f"[dim]Scanned:[/dim]  {s.requests_scanned}\n"
        f"[dim]Threats:[/dim]  {s.threats_detected}",
        title="🛡️ Auto-Protect Status", border_style=color))
    console.print()


@protect.command("off")
def protect_off():
    """Deactivate auto-protect."""
    from memgar.auto_protect import auto_protect_off
    auto_protect_off()
    console.print("[yellow]⚠️  Auto-protect deactivated.[/yellow]")


# =============================================================================
# LEDGER COMMAND GROUP — Memory Integrity Ledger
