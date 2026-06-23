"""`memgar identity` command group — per-agent identity / scoped tokens."""

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
def identity() -> None:
    """
    🪪 Per-agent identity — scoped tokens, delegation, audit trail.

    Every agent gets a unique cryptographic identity. Tokens are
    short-lived, scoped to specific capabilities, and revocable
    individually without affecting other agents.

    Commands:
        register   Register a new agent identity
        list       List all registered agents
        token      Issue a scoped token for an agent
        verify     Verify a token
        revoke     Revoke an agent (or a specific token)
        delegate   Delegate permissions from one agent to another
        audit      Show immutable audit log
        status     Show registry statistics
    """
    pass


def _get_reg(store):
    from memgar.identity import AgentRegistry
    return AgentRegistry(store_path=store)


@identity.command("register")
@click.argument("name")
@click.option("--scope", "-s", "scopes", multiple=True,
              help="Permission scope (repeatable). Use 'memgar identity scopes' to list.")
@click.option("--owner", required=True, help="Email of human owner")
@click.option("--description", "-d", default="")
@click.option("--ttl", default=300, type=int, help="Token TTL in seconds (default 300)")
@click.option("--expires-days", default=None, type=int, help="Agent identity expiry in days")
@click.option("--store", default="./memgar_agents.json", help="Registry store path")
@click.option("--json", "output_json", is_flag=True)
def identity_register(name, scopes, owner, description, ttl, expires_days, store, output_json):
    """
    Register a new agent identity with scoped permissions.

    \b
    Examples:
        memgar identity register email-processor \\
            --owner alice@corp.com \\
            --scope read_memory --scope send_email --scope scan_content

        memgar identity register finance-bot \\
            --owner cfo@corp.com \\
            --scope read_finances --scope write_finances \\
            --ttl 60 --expires-days 90
    """
    from memgar.identity import PermissionScope
    registry = _get_reg(store)

    # Parse scopes
    valid_scope_values = {s.value for s in PermissionScope}
    parsed_scopes = []
    for s in scopes:
        s_lower = s.lower()
        if s_lower not in valid_scope_values:
            console.print(f"[red]Unknown scope: {s}[/red]")
            console.print(f"[dim]Valid: {', '.join(sorted(valid_scope_values))}[/dim]")
            raise SystemExit(1)
        parsed_scopes.append(PermissionScope(s_lower))

    if not parsed_scopes:
        # Default: safe read-only scopes
        parsed_scopes = [PermissionScope.READ_MEMORY, PermissionScope.SCAN_CONTENT]
        if not output_json:
            console.print("[dim]No scopes specified — defaulting to read_memory + scan_content[/dim]")

    identity_obj = registry.register(
        name=name,
        scopes=parsed_scopes,
        owner=owner,
        description=description,
        ttl_seconds=ttl,
        agent_ttl_days=expires_days,
    )

    if output_json:
        console.print_json(json.dumps(identity_obj.to_dict(), indent=2))
        return

    console.print()
    sc_str = ", ".join(s.value for s in identity_obj.scopes)
    risk = " [red bold](HIGH RISK SCOPES)[/red bold]" if identity_obj.has_high_risk_scopes else ""
    body = (
        "[bold green]Agent registered[/bold green]\n\n"
        "[dim]ID:[/dim]       " + identity_obj.agent_id + "\n"
        "[dim]Name:[/dim]     " + identity_obj.name + "\n"
        "[dim]Owner:[/dim]    " + identity_obj.owner + "\n"
        "[dim]Scopes:[/dim]   " + sc_str + risk + "\n"
        "[dim]Token TTL:[/dim] " + str(identity_obj.token_ttl) + "s\n"
        "[dim]Expires:[/dim]  " + (identity_obj.expires_at[:10] if identity_obj.expires_at else "never")
    )
    console.print(Panel(body, title="Identity: " + name, border_style="green"))
    console.print()


@identity.command("list")
@click.option("--store", default="./memgar_agents.json")
@click.option("--status", default=None, type=click.Choice(["active","revoked","suspended","expired"]))
@click.option("--owner", default=None)
@click.option("--json", "output_json", is_flag=True)
def identity_list(store, status, owner, output_json):
    """List all registered agent identities."""
    from memgar.identity import AgentStatus
    if not Path(store).exists():
        console.print(f"[dim]No registry at {store}[/dim]"); return
    registry = _get_reg(store)
    status_filter = AgentStatus(status) if status else None
    agents = registry.list_agents(status=status_filter, owner=owner)

    if output_json:
        console.print_json(json.dumps([a.to_dict() for a in agents], indent=2)); return

    console.print()
    if not agents:
        console.print(Panel("[dim]No agents registered.[/dim]", title="Agent Registry")); return

    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Agent ID", width=18, style="cyan")
    tbl.add_column("Name", width=20)
    tbl.add_column("Status", width=10)
    tbl.add_column("Owner", width=22)
    tbl.add_column("Scopes", style="dim")
    sc_map = {"active": "green", "revoked": "red", "suspended": "yellow", "expired": "dim"}
    for a in agents:
        tc = sc_map.get(a.status.value, "white")
        scope_str = ", ".join(s.value for s in a.scopes[:3])
        if len(a.scopes) > 3:
            scope_str += f" +{len(a.scopes)-3}"
        tbl.add_row(a.agent_id[:16], a.name[:18],
                    "[" + tc + "]" + a.status.value + "[/" + tc + "]",
                    a.owner[:20], scope_str)
    console.print(tbl)
    console.print()


@identity.command("token")
@click.argument("agent_id")
@click.option("--principal", "-p", default=None, help="Human principal authorizing this action")
@click.option("--scope", "-s", "scopes", multiple=True, help="Requested scopes (subset of registered)")
@click.option("--ttl", default=None, type=int, help="Token TTL override")
@click.option("--store", default="./memgar_agents.json")
@click.option("--json", "output_json", is_flag=True)
def identity_token(agent_id, principal, scopes, ttl, store, output_json):
    """
    Issue a scoped access token for an agent.

    \b
    Examples:
        memgar identity token agt_abc123 --principal alice@corp.com
        memgar identity token agt_abc123 --scope scan_content --ttl 60
    """
    from memgar.identity import PermissionScope
    registry = _get_reg(store)
    parsed_scopes = None
    if scopes:
        try:
            parsed_scopes = [PermissionScope(s.lower()) for s in scopes]
        except ValueError as e:
            console.print(f"[red]{e}[/red]"); raise SystemExit(1)
    try:
        token = registry.issue_token(agent_id, scopes=parsed_scopes,
                                     principal=principal, ttl_seconds=ttl)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]"); raise SystemExit(1)

    if output_json:
        d = token.to_dict(); d["token_string"] = token.token_string
        console.print_json(json.dumps(d, indent=2)); return

    console.print()
    body = (
        "[bold green]Token issued[/bold green]\n\n"
        "[dim]JTI:[/dim]       " + token.jti + "\n"
        "[dim]Agent:[/dim]     " + token.agent_id + "\n"
        "[dim]Principal:[/dim] " + (token.principal or "-") + "\n"
        "[dim]Scopes:[/dim]    " + ", ".join(s.value for s in token.scopes) + "\n"
        "[dim]Expires in:[/dim] " + str(int(token.ttl_remaining)) + "s\n\n"
        "[dim bold]Token string:[/dim bold]\n" + token.token_string[:80] + "..."
    )
    console.print(Panel(body, title="Agent Token", border_style="blue"))
    console.print()


@identity.command("verify")
@click.argument("token_string")
@click.option("--scope", "-s", default=None, help="Required scope to check")
@click.option("--store", default="./memgar_agents.json")
@click.option("--json", "output_json", is_flag=True)
def identity_verify(token_string, scope, store, output_json):
    """Verify a token (and optionally check required scope)."""
    from memgar.identity import PermissionScope
    registry = _get_reg(store)
    required = PermissionScope(scope.lower()) if scope else None
    try:
        token = registry.verify_token(token_string, required_scope=required)
        if output_json:
            console.print_json(json.dumps(token.to_dict(), indent=2)); return
        console.print()
        console.print(Panel(
            "[bold green]VALID[/bold green]\n\n"
            "[dim]Agent:[/dim]  " + token.agent_id + "\n"
            "[dim]Scopes:[/dim] " + ", ".join(s.value for s in token.scopes) + "\n"
            "[dim]TTL:[/dim]    " + str(int(token.ttl_remaining)) + "s remaining\n"
            "[dim]Depth:[/dim]  " + str(token.delegation_depth),
            title="Token Verification", border_style="green"))
        console.print()
        raise SystemExit(0)
    except ValueError as e:
        if output_json:
            console.print_json(json.dumps({"valid": False, "error": str(e)}, indent=2))
        else:
            console.print(Panel("[bold red]INVALID[/bold red]\n\n" + str(e),
                                title="Token Verification", border_style="red"))
        raise SystemExit(1)


@identity.command("revoke")
@click.argument("agent_id")
@click.option("--reason", "-r", default="", help="Reason for revocation")
@click.option("--token-jti", default=None, help="Revoke a specific token instead of the agent")
@click.option("--by", default="cli", help="Who is revoking")
@click.option("--store", default="./memgar_agents.json")
def identity_revoke(agent_id, reason, token_jti, by, store):
    """
    Revoke an agent identity (or a specific token).

    Revoking an agent blocks ALL future tokens for that agent.
    Other agents are completely unaffected.

    Revoking a token (--token-jti) only invalidates that one token.
    """
    registry = _get_reg(store)
    if token_jti:
        registry.revoke_token(token_jti)
        console.print(f"[yellow]Token revoked:[/yellow] {token_jti}")
        return
    ok = registry.revoke(agent_id, reason=reason, revoked_by=by)
    if ok:
        console.print(f"[red]Agent revoked:[/red] {agent_id}" + (f" — {reason}" if reason else ""))
    else:
        console.print(f"[red]Agent not found: {agent_id}[/red]"); raise SystemExit(1)


@identity.command("audit")
@click.option("--agent-id", default=None)
@click.option("--limit", default=20, type=int)
@click.option("--store", default="./memgar_agents.json")
@click.option("--json", "output_json", is_flag=True)
@click.option("--verify-chain", is_flag=True, help="Verify audit log integrity")
def identity_audit(agent_id, limit, store, output_json, verify_chain):
    """
    Show the immutable audit log.

    Every register, token issue, scope check, revocation is logged
    with a SHA-256 hash chain — tamper-evident.

    \b
    Examples:
        memgar identity audit
        memgar identity audit --agent-id agt_abc123 --limit 50
        memgar identity audit --verify-chain
    """
    if not Path(store).exists():
        console.print(f"[dim]No registry at {store}[/dim]"); return
    registry = _get_reg(store)

    if verify_chain:
        valid, errors = registry.verify_audit_chain()
        if valid:
            console.print("[green]Audit chain: VALID[/green]")
        else:
            console.print(f"[red]Audit chain: TAMPERED ({errors} errors)[/red]")
        return

    events = registry.audit_log(agent_id=agent_id, limit=limit)
    if output_json:
        console.print_json(json.dumps([e.to_dict() for e in events], indent=2)); return

    console.print()
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Timestamp", width=22, style="dim")
    tbl.add_column("Agent", width=18, style="cyan")
    tbl.add_column("Action", width=16)
    tbl.add_column("Principal", width=20)
    tbl.add_column("Result", width=8)
    rc = {"allowed": "green", "denied": "red"}
    for e in events:
        tc = rc.get(e.result, "yellow")
        tbl.add_row(e.timestamp[:19], e.agent_id[:16], e.action,
                    (e.principal or "-")[:18],
                    "[" + tc + "]" + e.result + "[/" + tc + "]")
    console.print(tbl)
    console.print()


@identity.command("status")
@click.option("--store", default="./memgar_agents.json")
@click.option("--json", "output_json", is_flag=True)
def identity_status(store, output_json):
    """Show registry statistics."""
    if not Path(store).exists():
        console.print(f"[dim]No registry at {store}[/dim]"); return
    registry = _get_reg(store)
    st = registry.stats()
    if output_json:
        console.print_json(json.dumps(st, indent=2)); return
    console.print()
    console.print(Panel(
        "[dim]Total agents:[/dim]   " + str(st["total_agents"]) + "\n"
        "[dim]Active:[/dim]         [green]" + str(st["active"]) + "[/green]\n"
        "[dim]Revoked:[/dim]        [red]" + str(st["revoked"]) + "[/red]\n"
        "[dim]Suspended:[/dim]      [yellow]" + str(st["suspended"]) + "[/yellow]\n"
        "[dim]Revoked tokens:[/dim] " + str(st["revoked_tokens"]) + "\n"
        "[dim]Delegations:[/dim]    " + str(st["delegations"]) + "\n"
        "[dim]Audit events:[/dim]   " + str(st["audit_events"]),
        title="Identity Registry Status", border_style="blue"))
    console.print()


@identity.command("scopes")
def identity_scopes():
    """List all available permission scopes."""
    from memgar.identity import HIGH_RISK_SCOPES, PermissionScope
    console.print()
    tbl = Table(box=box.SIMPLE, show_header=True, title="Available Permission Scopes")
    tbl.add_column("Scope", style="cyan", width=22)
    tbl.add_column("Risk", width=8)
    tbl.add_column("Description", style="dim")
    desc = {
        "read_memory": "Read from agent memory store",
        "write_memory": "Write to agent memory store",
        "delete_memory": "Delete memory entries",
        "scan_content": "Run Memgar threat scan",
        "send_email": "Send emails",
        "send_slack": "Post to Slack",
        "send_telegram": "Send Telegram messages",
        "send_webhook": "Call webhooks",
        "read_files": "Read files from disk",
        "write_files": "Write files to disk",
        "delete_files": "Delete files",
        "execute_code": "Execute code/scripts",
        "run_shell": "Run shell commands",
        "read_database": "Read from databases",
        "write_database": "Write to databases",
        "delete_database": "Delete database records",
        "read_finances": "Read financial data",
        "write_finances": "Write financial records",
        "transfer_funds": "Transfer money",
        "call_apis": "Call external APIs",
        "browse_web": "Browse the web",
        "manage_agents": "Register/revoke agents",
        "read_audit_log": "Read audit logs",
        "delegate": "Sub-delegate to other agents",
        "*": "Full access (admin only)",
    }
    for scope in PermissionScope:
        risk = "[red]HIGH[/red]" if scope in HIGH_RISK_SCOPES else "[green]low[/green]"
        tbl.add_row(scope.value, risk, desc.get(scope.value, ""))
    console.print(tbl)
    console.print()
