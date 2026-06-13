"""`memgar siem` command group — SIEM integration (Splunk/Datadog/Elastic/Syslog)."""

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
def siem() -> None:
    """
    📡 SIEM integration — stream events to Splunk, Datadog, Elastic, Syslog.

    Commands:
        test      Send a test event to configured SIEM sinks
        stream    Stream Memgar audit log events to SIEM
        config    Show current SIEM configuration
        convert   Convert a Memgar JSON report to OCSF format
    """
    pass


def _build_router_from_opts(splunk_url, splunk_token, datadog_key, datadog_site,
                              elastic_url, elastic_key, syslog_host, syslog_port,
                              syslog_proto, webhook, log_file, min_severity):
    from memgar.siem import (
        DatadogSink,
        ElasticSink,
        FileSink,
        SIEMRouter,
        SplunkHECSink,
        SyslogSink,
        WebhookSink,
    )
    router = SIEMRouter(min_severity=min_severity, async_mode=False)
    if splunk_url or os.environ.get("MEMGAR_SPLUNK_HEC_URL"):
        router.add_sink(SplunkHECSink(url=splunk_url, token=splunk_token))
    if datadog_key or os.environ.get("MEMGAR_DATADOG_API_KEY"):
        router.add_sink(DatadogSink(api_key=datadog_key, site=datadog_site))
    if elastic_url or os.environ.get("MEMGAR_ELASTIC_URL"):
        router.add_sink(ElasticSink(url=elastic_url, api_key=elastic_key))
    if syslog_host or os.environ.get("MEMGAR_SYSLOG_HOST"):
        router.add_sink(SyslogSink(host=syslog_host, port=syslog_port, protocol=syslog_proto))
    if webhook or os.environ.get("MEMGAR_SIEM_WEBHOOK"):
        router.add_sink(WebhookSink(url=webhook))
    if log_file:
        router.add_sink(FileSink(path=log_file))
    return router


def _siem_options(fn):
    """Shared SIEM connection options decorator."""
    for opt in reversed([
        click.option("--splunk-url", default=None, help="Splunk HEC URL"),
        click.option("--splunk-token", default=None, help="Splunk HEC token"),
        click.option("--datadog-key", default=None, help="Datadog API key"),
        click.option("--datadog-site", default="datadoghq.com"),
        click.option("--elastic-url", default=None, help="Elasticsearch URL"),
        click.option("--elastic-key", default=None, help="Elasticsearch API key"),
        click.option("--syslog-host", default=None, help="Syslog server host"),
        click.option("--syslog-port", default=514, type=int),
        click.option("--syslog-proto", default="udp", type=click.Choice(["udp","tcp","tls"])),
        click.option("--webhook", default=None, help="Generic webhook URL"),
        click.option("--log-file", default=None, help="Write OCSF JSONL to file (- = stdout)"),
        click.option("--min-severity", default="low", type=click.Choice(["info","low","medium","high","critical"])),
    ]):
        fn = opt(fn)
    return fn


@siem.command("test")
@_siem_options
@click.option("--json", "output_json", is_flag=True)
def siem_test(splunk_url, splunk_token, datadog_key, datadog_site, elastic_url,
              elastic_key, syslog_host, syslog_port, syslog_proto, webhook,
              log_file, min_severity, output_json):
    """
    Send a test event to all configured SIEM sinks.

    \b
    Examples:
        memgar siem test --log-file -
        memgar siem test --splunk-url https://splunk:8088 --splunk-token TOKEN
        memgar siem test --datadog-key DD_API_KEY
        memgar siem test --syslog-host 192.168.1.100 --syslog-proto tcp
    """
    from memgar.siem import SIEMEvent

    router = _build_router_from_opts(
        splunk_url, splunk_token, datadog_key, datadog_site,
        elastic_url, elastic_key, syslog_host, syslog_port, syslog_proto,
        webhook, log_file, min_severity
    )

    if not router._sinks:
        console.print("[yellow]No SIEM sinks configured.[/yellow]")
        console.print("[dim]Set environment variables or pass flags:[/dim]")
        console.print("[dim]  MEMGAR_SPLUNK_HEC_URL + MEMGAR_SPLUNK_HEC_TOKEN[/dim]")
        console.print("[dim]  MEMGAR_DATADOG_API_KEY[/dim]")
        console.print("[dim]  MEMGAR_ELASTIC_URL[/dim]")
        console.print("[dim]  MEMGAR_SYSLOG_HOST[/dim]")
        console.print("[dim]  MEMGAR_SIEM_WEBHOOK[/dim]")
        console.print("[dim]  --log-file - (stdout)[/dim]")
        return

    event = SIEMEvent.threat_detected(
        threat_id="TEST-001",
        threat_name="Memgar SIEM Test Event",
        content="This is a test event from Memgar v0.5.10",
        risk_score=42,
        severity="medium",
    )

    if output_json:
        console.print_json(json.dumps(event.to_ocsf(), indent=2))
        return

    console.print()
    results = {}
    for sink in router._sinks:
        with console.status(f"[bold blue]Sending to {sink.name}...[/bold blue]"):
            ok = sink.send_one(event)
        results[sink.name] = ok
        color = "green" if ok else "red"
        console.print(f"  [{color}]{'✅' if ok else '❌'} {sink.name}[/{color}]")

    console.print()
    all_ok = all(results.values())
    console.print(Panel(
        "[bold green]All sinks OK[/bold green]" if all_ok
        else "[bold red]Some sinks failed[/bold red]",
        title="SIEM Test", border_style="green" if all_ok else "red"))
    console.print()
    raise SystemExit(0 if all_ok else 1)


@siem.command("stream")
@click.argument("path", type=click.Path(exists=True))
@_siem_options
@click.option("--type", "source_type",
              type=click.Choice(["ledger", "forensics", "supply", "identity", "auto"]),
              default="auto", help="Source type (default: auto-detect)")
@click.option("--json", "output_json", is_flag=True)
def siem_stream(path, splunk_url, splunk_token, datadog_key, datadog_site,
                elastic_url, elastic_key, syslog_host, syslog_port, syslog_proto,
                webhook, log_file, min_severity, source_type, output_json):
    """
    Stream findings from a Memgar report to SIEM.

    Reads a Memgar JSON report (ledger, forensics, supply scan) and
    forwards events to configured SIEM sinks.

    \b
    Examples:
        memgar siem stream ./forensics_report.json --log-file -
        memgar siem stream ./supply_report.json --splunk-url URL --splunk-token TOKEN
        memgar siem stream ./agent.ledger.json --datadog-key KEY
    """
    from memgar.siem import EventCategory, SIEMEvent

    router = _build_router_from_opts(
        splunk_url, splunk_token, datadog_key, datadog_site,
        elastic_url, elastic_key, syslog_host, syslog_port, syslog_proto,
        webhook, log_file or "-", min_severity
    )

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    events = []

    # Auto-detect or use specified type
    if source_type == "auto":
        if "entries" in data and "meta" in data:
            source_type = "ledger"
        elif "findings" in data and "packages_found" in data:
            source_type = "supply"
        elif "poisoned_entries" in data or "is_compromised" in data:
            source_type = "forensics"
        else:
            source_type = "generic"

    if source_type == "supply":
        for f in data.get("findings", []):
            if f.get("severity") in ("critical", "high", "medium"):
                events.append(SIEMEvent.supply_chain_threat(
                    package=f["package"], version=f.get("version"),
                    finding_type=f["finding_type"], severity=f["severity"],
                    description=f["description"], cve=f.get("cve"),
                ))

    elif source_type == "ledger":
        report = data
        if not report.get("is_valid", True):
            events.append(SIEMEvent.ledger_tamper(
                ledger_path=path,
                tampered_count=report.get("tampered_count", 0),
                first_breach=report.get("first_breach_index"),
            ))

    elif source_type == "forensics":
        for entry in data.get("poisoned", data.get("entries", [])):
            if entry.get("is_poisoned"):
                events.append(SIEMEvent(
                    category=EventCategory.FORENSICS_FINDING,
                    severity=entry.get("severity", "high"),
                    message="Forensics: poisoned memory entry detected",
                    content_preview=str(entry.get("content", ""))[:100],
                    threat_id=str(entry.get("threat_ids", [""])[0]) if entry.get("threat_ids") else None,
                    action="detected",
                ))

    if output_json:
        console.print_json(json.dumps([e.to_ocsf() for e in events], indent=2))
        return

    console.print()
    if not events:
        console.print(Panel("[green]No findings to stream.[/green]", title="SIEM Stream"))
        return

    with console.status(f"[bold blue]Streaming {len(events)} events...[/bold blue]"):
        for ev in events:
            router.emit(ev)
        router.flush()

    st = router.stats()
    console.print(Panel(
        f"[dim]Events emitted:[/dim] {st['emitted']}\n"
        f"[dim]Sent:[/dim]          [green]{st['sent']}[/green]\n"
        f"[dim]Failed:[/dim]        [red]{st['failed']}[/red]",
        title="SIEM Stream Complete", border_style="green"))
    console.print()


@siem.command("config")
def siem_config():
    """Show current SIEM configuration from environment variables."""
    env_vars = {
        "MEMGAR_SPLUNK_HEC_URL":    os.environ.get("MEMGAR_SPLUNK_HEC_URL", ""),
        "MEMGAR_SPLUNK_HEC_TOKEN":  "***" if os.environ.get("MEMGAR_SPLUNK_HEC_TOKEN") else "",
        "MEMGAR_DATADOG_API_KEY":   "***" if os.environ.get("MEMGAR_DATADOG_API_KEY") else "",
        "MEMGAR_DATADOG_SITE":      os.environ.get("MEMGAR_DATADOG_SITE", ""),
        "MEMGAR_ELASTIC_URL":       os.environ.get("MEMGAR_ELASTIC_URL", ""),
        "MEMGAR_ELASTIC_API_KEY":   "***" if os.environ.get("MEMGAR_ELASTIC_API_KEY") else "",
        "MEMGAR_SYSLOG_HOST":       os.environ.get("MEMGAR_SYSLOG_HOST", ""),
        "MEMGAR_SYSLOG_PORT":       os.environ.get("MEMGAR_SYSLOG_PORT", ""),
        "MEMGAR_SIEM_WEBHOOK":      os.environ.get("MEMGAR_SIEM_WEBHOOK", ""),
    }
    console.print()
    tbl = Table(box=box.SIMPLE, show_header=True, title="SIEM Configuration")
    tbl.add_column("Variable", style="cyan", width=30)
    tbl.add_column("Value", width=40)
    for k, v in env_vars.items():
        color = "green" if v else "dim"
        tbl.add_row(k, "[" + color + "]" + (v or "not set") + "[/" + color + "]")
    console.print(tbl)
    console.print()


@siem.command("convert")
@click.argument("input_path", type=click.Path(exists=True))
@click.option("--format", "fmt", type=click.Choice(["ocsf","cef","leef"]), default="ocsf")
@click.option("--output", "-o", default=None)
def siem_convert(input_path, fmt, output):
    """
    Convert a Memgar event/report to OCSF, CEF, or LEEF format.

    \b
    Examples:
        memgar siem convert ./threat_event.json --format ocsf
        memgar siem convert ./report.json --format cef --output events.cef
    """
    from memgar.siem import EventCategory, SIEMEvent
    data = json.loads(Path(input_path).read_text())

    # Try to parse as a single SIEMEvent or list
    events_data = data if isinstance(data, list) else [data]
    lines = []
    for d in events_data:
        try:
            ev = SIEMEvent(
                category=EventCategory(d.get("category", "threat_detected")),
                severity=d.get("severity", "medium"),
                message=d.get("message", ""),
                threat_id=d.get("threat_id"),
                risk_score=d.get("risk_score"),
                agent_id=d.get("agent_id"),
                action=d.get("action", "detected"),
            )
            if fmt == "cef":
                lines.append(ev.to_cef())
            elif fmt == "leef":
                lines.append(ev.to_leef())
            else:
                lines.append(json.dumps(ev.to_ocsf()))
        except Exception:
            lines.append(json.dumps(d))

    result = "\n".join(lines)
    if output:
        Path(output).write_text(result)
        console.print(f"[green]Converted {len(lines)} events → {output}[/green]")
    else:
        console.print(result)
