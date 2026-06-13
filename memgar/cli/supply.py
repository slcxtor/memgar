"""`memgar supply` command group — supply chain scanner."""

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
def supply() -> None:
    """
    🔗 Supply chain attack scanner.

    Detects malicious packages, typosquatting, backdoored versions,
    and suspicious install-time code in dependency files.

    Commands:
        scan    Scan a directory or file for supply chain threats
        check   Check a single package name/version
        list    Show known malicious packages database
    """
    pass


@supply.command("scan")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Save report to file (.json)")
@click.option("--no-typo", is_flag=True, help="Disable typosquatting detection")
@click.option("--no-unpinned", is_flag=True, help="Suppress unpinned version warnings")
@click.option("--min-severity", type=click.Choice(["info","low","medium","high","critical"]),
              default="medium", help="Minimum severity to report (default: medium)")
@click.option("--json", "output_json", is_flag=True)
def supply_scan(path, output, no_typo, no_unpinned, min_severity, output_json):
    """
    Scan dependency files for supply chain threats.

    Checks requirements.txt, pyproject.toml, setup.py, Pipfile,
    environment.yaml and .pth files.

    \b
    Examples:
        memgar supply scan ./
        memgar supply scan ./requirements.txt
        memgar supply scan ./ --output supply_report.json
        memgar supply scan ./ --no-typo --min-severity high
    """
    from memgar.supply import SupplyChainScanner

    scanner = SupplyChainScanner(
        check_typosquatting=not no_typo,
        check_unpinned=not no_unpinned,
    )

    with console.status("[bold blue]Scanning supply chain...[/bold blue]"):
        p = Path(path)
        if p.is_file():
            report = scanner.scan_file(path)
        else:
            report = scanner.scan_directory(path)

    # Filter by min severity
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev = sev_order.get(min_severity, 2)
    visible = [f for f in report.findings if sev_order.get(f.severity.value, 0) >= min_sev]

    if output:
        Path(output).write_text(report.to_json())

    if output_json:
        console.print_json(report.to_json())
        raise SystemExit(2 if report.has_critical else (1 if report.has_high else 0))

    color = "red" if report.has_critical else ("orange1" if report.has_high else "green")
    status = "CRITICAL THREATS" if report.has_critical else ("HIGH RISKS" if report.has_high else "CLEAN")
    console.print()
    body = (
        "[bold " + color + "]" + status + "[/bold " + color + "]\n\n"
        "[dim]Files scanned:[/dim]   " + str(len(report.scanned_files)) + "\n"
        "[dim]Packages found:[/dim]  " + str(report.packages_found) + "\n"
        "[dim]Critical:[/dim]        [red]" + str(report.critical_count) + "[/red]\n"
        "[dim]High:[/dim]            [orange1]" + str(report.high_count) + "[/orange1]\n"
        "[dim]Duration:[/dim]        " + str(round(report.scan_duration_ms)) + "ms"
    )
    if output:
        body += "\n[dim]Report:[/dim]          " + output
    console.print(Panel(body, title="Supply Chain Scan", border_style=color))

    if visible:
        tbl = Table(box=box.SIMPLE, show_header=True)
        tbl.add_column("Sev", width=8)
        tbl.add_column("Type", width=18)
        tbl.add_column("Package", width=22)
        tbl.add_column("File", width=20)
        tbl.add_column("Description", style="dim")
        sc = {"critical": "red bold", "high": "orange1", "medium": "yellow", "low": "green"}
        for f in visible[:30]:
            tc = sc.get(f.severity.value, "white")
            console.print()
            console.print(
                "[" + tc + "]" + f.severity.value.upper() + "[/" + tc + "]  "
                "[bold]" + f.package + ("[/" + f.version + "]" if f.version else "") + "[/bold]"
                " — " + f.description[:120]
            )
            if f.remediation:
                console.print("  [dim]Fix: " + f.remediation[:100] + "[/dim]")
            if f.cve:
                console.print("  [dim]CVE: " + f.cve + "[/dim]")

    console.print()
    exit_code = 2 if report.has_critical else (1 if report.has_high else 0)
    raise SystemExit(exit_code)


@supply.command("check")
@click.argument("package")
@click.option("--version", "-v", default=None, help="Package version to check")
@click.option("--json", "output_json", is_flag=True)
def supply_check(package, version, output_json):
    """
    Check a single package for supply chain threats.

    \b
    Examples:
        memgar supply check litellm
        memgar supply check litellm --version 1.82.7
        memgar supply check telnyx -v 4.87.1
    """
    from memgar.supply import SupplyChainScanner
    scanner = SupplyChainScanner()
    findings = scanner.check_package(package, version)

    if output_json:
        console.print_json(json.dumps([f.to_dict() for f in findings], indent=2))
        raise SystemExit(2 if any(f.severity.value == "critical" for f in findings) else 0)

    console.print()
    if not findings:
        console.print(Panel(
            "[green]No threats detected for " + package + (("==" + version) if version else "") + "[/green]",
            title="Supply Chain Check", border_style="green"))
    else:
        sc = {"critical": "red bold", "high": "orange1", "medium": "yellow"}
        for f in findings:
            tc = sc.get(f.severity.value, "white")
            body = (
                "[" + tc + "][bold]" + f.severity.value.upper() + "[/bold][/" + tc + "]\n\n"
                "[dim]Type:[/dim]        " + f.finding_type.value + "\n"
                "[dim]Package:[/dim]     " + f.package + ((" v" + f.version) if f.version else "") + "\n"
                "[dim]Description:[/dim] " + f.description + "\n"
            )
            if f.cve:
                body += "[dim]CVE:[/dim]         " + f.cve + "\n"
            if f.similar_to:
                body += "[dim]Similar to:[/dim]  " + f.similar_to + "\n"
            body += "[dim]Fix:[/dim]         " + f.remediation
            console.print(Panel(body, title="Finding: " + f.package, border_style=tc))
    console.print()
    raise SystemExit(2 if any(f.severity.value in ("critical","high") for f in findings) else 0)


@supply.command("list")
@click.option("--json", "output_json", is_flag=True)
def supply_list(output_json):
    """Show the known malicious packages database."""
    from memgar.supply import KNOWN_MALICIOUS
    if output_json:
        console.print_json(json.dumps(KNOWN_MALICIOUS, indent=2))
        return
    console.print()
    tbl = Table(box=box.SIMPLE, show_header=True, title="Known Malicious Packages")
    tbl.add_column("Package", style="cyan", width=22)
    tbl.add_column("Versions", width=18)
    tbl.add_column("Severity", width=10)
    tbl.add_column("CVE", width=20)
    tbl.add_column("Description", style="dim")
    sc = {"critical": "red bold", "high": "orange1", "medium": "yellow"}
    for pkg, info in sorted(KNOWN_MALICIOUS.items()):
        tc = sc.get(info.get("severity", "high"), "white")
        vers = ", ".join(info.get("versions", ["*"])[:3])
        tbl.add_row(
            pkg,
            vers,
            "[" + tc + "]" + info.get("severity","?").upper() + "[/" + tc + "]",
            info.get("cve", "-"),
            info.get("description", "")[:60],
        )
    console.print(tbl)
    console.print()
