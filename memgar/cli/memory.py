"""`memgar memory` command group — MemoryVault snapshot forensics."""

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


@main.group("memory")
def memory_group() -> None:
    """
    🧠 Memory forensics — inspect, diff, verify, and roll back vault snapshots.

    Operates on a `MemoryVault` SQLite database (typically created by the
    runtime with `MemoryVault(db_path=...)`). All commands are read-only by
    default; `rollback --apply` is the only mutating operation and requires
    explicit confirmation.

    Commands:
        list     List every snapshot in the vault
        inspect  Show the contents of one snapshot
        diff     Compare two snapshots (added / deleted / modified)
        verify   Recompute root hash + verify signature
        rollback Plan or apply a rollback to a specific snapshot
        replay   Render snapshot timeline as an ASCII forensic trail

    Exit codes:
        0   success / integrity OK
        1   user error (bad path, missing snapshot)
        2   integrity violation (root-hash or signature mismatch)
    """
    pass


def _open_vault(path: str, public_key_b64: Optional[str] = None):
    """Open an existing vault DB. Loads snapshots from SQLite on init."""
    from memgar.memory_vault import MemoryVault
    if not Path(path).exists():
        console.print(f"[red]Error:[/red] vault DB not found: {path}")
        raise SystemExit(1)
    public_key = None
    if public_key_b64:
        try:
            public_key = MemoryVault.public_key_from_b64(public_key_b64)
        except Exception as exc:  # noqa: BLE001
            console.print(f"[red]Error:[/red] invalid public key: {exc}")
            raise SystemExit(1)
    return MemoryVault(db_path=path, public_key=public_key)


def _resolve_snapshot(vault, snapshot_id: Optional[str]):
    """Resolve a snapshot by full ID, prefix, or None=latest. Exit 1 if missing."""
    snap = vault._get_snapshot(snapshot_id)  # noqa: SLF001
    if snap is None:
        label = repr(snapshot_id) if snapshot_id else "latest"
        console.print(f"[red]Error:[/red] snapshot {label} not found")
        raise SystemExit(1)
    return snap


def _format_ts(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


@memory_group.command("list")
@click.argument("vault_path", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="JSON output for scripting")
@click.option("--limit", default=50, type=int, help="Show only the last N snapshots")
def memory_list(vault_path: str, output_json: bool, limit: int) -> None:
    """
    List every snapshot in the vault.

    \b
    Examples:
        memgar memory list ./vault.db
        memgar memory list ./vault.db --limit 10 --json
    """
    vault = _open_vault(vault_path)
    with vault._lock:  # noqa: SLF001
        snapshots = list(vault._snapshots)  # noqa: SLF001
    snapshots = snapshots[-limit:]

    if output_json:
        out = [
            {
                "id": s.id,
                "label": s.label,
                "ts": s.ts,
                "ts_iso": _format_ts(s.ts),
                "entry_count": s.entry_count,
                "root_hash": s.root_hash,
                "signed": bool(s.signed),
            }
            for s in snapshots
        ]
        console.print_json(json.dumps(out, indent=2))
        return

    if not snapshots:
        console.print(
            Panel(
                "[yellow]Vault is empty — no snapshots have been taken yet.[/yellow]\n\n"
                "[dim]The runtime takes snapshots via "
                "`vault.take_snapshot(label=...)`.[/dim]",
                title="🧠 Memory Vault",
                border_style="yellow",
            )
        )
        return

    table = Table(
        title=f"🧠 Memory Vault — {Path(vault_path).name}  "
              f"({len(snapshots)} snapshot{'s' if len(snapshots) != 1 else ''})",
        box=box.SIMPLE,
        show_header=True,
    )
    table.add_column("#", justify="right", style="dim", width=4)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Timestamp", width=22)
    table.add_column("Entries", justify="right", width=8)
    table.add_column("Signed", width=8)
    table.add_column("Root hash", style="dim", width=20)
    table.add_column("Label")
    for idx, snap in enumerate(snapshots):
        signed_glyph = "[green]✓[/green]" if snap.signed else "[dim]–[/dim]"
        table.add_row(
            str(idx),
            snap.id[:8],
            _format_ts(snap.ts),
            str(snap.entry_count),
            signed_glyph,
            snap.root_hash[:18] + "…",
            snap.label or "[dim](unlabeled)[/dim]",
        )
    console.print()
    console.print(table)
    console.print()


@memory_group.command("inspect")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("snapshot_id", required=False)
@click.option("--latest", is_flag=True, help="Inspect the most recent snapshot")
@click.option("--full", is_flag=True, help="Show full entry content (default: 80-char preview)")
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_inspect(
    vault_path: str,
    snapshot_id: Optional[str],
    latest: bool,
    full: bool,
    output_json: bool,
) -> None:
    """
    Show the contents of a snapshot.

    \b
    Examples:
        memgar memory inspect ./vault.db --latest
        memgar memory inspect ./vault.db 7a3f9b1c
        memgar memory inspect ./vault.db 7a3f9b1c --full --json
    """
    if not snapshot_id and not latest:
        console.print("[red]Error:[/red] provide SNAPSHOT_ID or --latest")
        raise SystemExit(1)
    vault = _open_vault(vault_path)
    snap = _resolve_snapshot(vault, None if latest else snapshot_id)

    if output_json:
        payload = {
            "id": snap.id,
            "label": snap.label,
            "ts": snap.ts,
            "ts_iso": _format_ts(snap.ts),
            "entry_count": snap.entry_count,
            "root_hash": snap.root_hash,
            "signed": bool(snap.signed),
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "content_hash": e.content_hash,
                    "content": e.content if full else (e.content[:80] + ("…" if len(e.content) > 80 else "")),
                    "source_type": e.source_type,
                    "source_id": e.source_id,
                    "captured_ts": e.captured_ts,
                    "metadata": e.metadata,
                }
                for e in snap.entries.values()
            ],
        }
        console.print_json(json.dumps(payload, indent=2))
        return

    signed = "[green]signed[/green]" if snap.signed else "[dim]unsigned[/dim]"
    console.print()
    console.print(
        Panel(
            f"[bold]ID:[/bold]         {snap.id}\n"
            f"[bold]Label:[/bold]      {snap.label or '[dim](none)[/dim]'}\n"
            f"[bold]Timestamp:[/bold]  {_format_ts(snap.ts)}\n"
            f"[bold]Entries:[/bold]    {snap.entry_count}\n"
            f"[bold]Root hash:[/bold]  [cyan]{snap.root_hash}[/cyan]\n"
            f"[bold]Signature:[/bold]  {signed}",
            title=f"🧠 Snapshot {snap.id[:8]}",
            border_style="cyan",
        )
    )

    if not snap.entries:
        console.print("[dim](snapshot has no entries)[/dim]\n")
        return

    table = Table(box=box.SIMPLE, show_header=True)
    table.add_column("Entry ID", style="cyan", width=22)
    table.add_column("Source", width=18)
    table.add_column("Hash", style="dim", width=14)
    table.add_column("Content" + (" (full)" if full else " (preview)"))
    for entry in snap.entries.values():
        source = (
            f"{entry.source_type}:{entry.source_id[:8]}"
            if entry.source_id
            else entry.source_type
        )
        content = entry.content if full else entry.content[:80]
        if not full and len(entry.content) > 80:
            content = content + "…"
        table.add_row(
            entry.entry_id[:20] + ("…" if len(entry.entry_id) > 20 else ""),
            source[:16] + ("…" if len(source) > 16 else ""),
            entry.content_hash[:12],
            content,
        )
    console.print(table)
    console.print()


@memory_group.command("diff")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("snapshot_a")
@click.argument("snapshot_b", required=False)
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_diff(
    vault_path: str,
    snapshot_a: str,
    snapshot_b: Optional[str],
    output_json: bool,
) -> None:
    """
    Compare two snapshots — show added, deleted, and modified entries.

    If SNAPSHOT_B is omitted, compare SNAPSHOT_A against the current live vault.

    \b
    Examples:
        memgar memory diff ./vault.db 7a3f9b1c
        memgar memory diff ./vault.db 7a3f9b1c ec88a02f
        memgar memory diff ./vault.db 7a3f9b1c ec88a02f --json
    """
    vault = _open_vault(vault_path)
    _resolve_snapshot(vault, snapshot_a)
    if snapshot_b:
        _resolve_snapshot(vault, snapshot_b)
    delta = vault.diff(snapshot_a_id=snapshot_a, snapshot_b_id=snapshot_b)

    if output_json:
        payload = {
            "snapshot_a_id": delta.snapshot_a_id,
            "snapshot_b_id": delta.snapshot_b_id,
            "added": delta.added,
            "deleted": delta.deleted,
            "modified": [
                {
                    "entry_id": m.entry_id,
                    "hash_before": m.hash_before,
                    "hash_after": m.hash_after,
                    "content_before": m.content_before,
                    "content_after": m.content_after,
                }
                for m in delta.modified
            ],
            "total_changes": delta.total_changes,
            "is_clean": delta.is_clean,
        }
        console.print_json(json.dumps(payload, indent=2))
        raise SystemExit(0 if delta.is_clean else 2)

    color = "green" if delta.is_clean else "yellow"
    label_b = delta.snapshot_b_id if snapshot_b else "live"
    console.print()
    console.print(
        Panel(
            f"[bold]A:[/bold]      {delta.snapshot_a_id[:24]}\n"
            f"[bold]B:[/bold]      {label_b[:24] if isinstance(label_b, str) else label_b}\n"
            f"[bold]Added:[/bold]    [green]{len(delta.added)}[/green]\n"
            f"[bold]Deleted:[/bold]  [red]{len(delta.deleted)}[/red]\n"
            f"[bold]Modified:[/bold] [yellow]{len(delta.modified)}[/yellow]",
            title="🧠 Memory Vault Diff",
            border_style=color,
        )
    )

    if delta.added:
        console.print("[bold green]+ Added[/bold green]")
        for eid in delta.added[:50]:
            console.print(f"  [green]+[/green] {eid}")
        if len(delta.added) > 50:
            console.print(f"  [dim]… and {len(delta.added) - 50} more[/dim]")
    if delta.deleted:
        console.print("[bold red]- Deleted[/bold red]")
        for eid in delta.deleted[:50]:
            console.print(f"  [red]-[/red] {eid}")
        if len(delta.deleted) > 50:
            console.print(f"  [dim]… and {len(delta.deleted) - 50} more[/dim]")
    if delta.modified:
        console.print("[bold yellow]~ Modified[/bold yellow]")
        for m in delta.modified[:20]:
            console.print(f"  [yellow]~[/yellow] {m.entry_id}")
            console.print(f"      [dim]before:[/dim] {m.content_before[:80]}")
            console.print(f"      [dim]after :[/dim] {m.content_after[:80]}")
        if len(delta.modified) > 20:
            console.print(f"  [dim]… and {len(delta.modified) - 20} more[/dim]")
    console.print()
    raise SystemExit(0 if delta.is_clean else 2)


@memory_group.command("verify")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("snapshot_id", required=False)
@click.option("--latest", is_flag=True, help="Verify the most recent snapshot")
@click.option(
    "--public-key",
    "public_key_b64",
    default=None,
    help="Ed25519 public key (base64) for signature verification",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_verify(
    vault_path: str,
    snapshot_id: Optional[str],
    latest: bool,
    public_key_b64: Optional[str],
    output_json: bool,
) -> None:
    """
    Verify snapshot integrity — recompute root hash and check Ed25519 signature.

    \b
    Examples:
        memgar memory verify ./vault.db --latest
        memgar memory verify ./vault.db 7a3f9b1c --public-key <b64>
        memgar memory verify ./vault.db 7a3f9b1c --json
    """
    if not snapshot_id and not latest:
        console.print("[red]Error:[/red] provide SNAPSHOT_ID or --latest")
        raise SystemExit(1)
    vault = _open_vault(vault_path, public_key_b64=public_key_b64)
    snap = _resolve_snapshot(vault, None if latest else snapshot_id)
    result = vault.verify_snapshot(snap.id)

    if output_json:
        payload = {
            "snapshot_id": result.snapshot_id,
            "verified_at": result.verified_at,
            "is_valid": result.is_valid,
            "signature_valid": result.signature_valid,
            "root_hash_match": result.root_hash_match,
            "tampered_ids": result.tampered_ids,
            "violations": result.violations,
        }
        console.print_json(json.dumps(payload, indent=2))
        raise SystemExit(0 if result.is_valid else 2)

    color = "green" if result.is_valid else "red"
    sig_label = (
        "[dim]unsigned[/dim]"
        if result.signature_valid is None
        else ("[green]valid[/green]" if result.signature_valid else "[red]INVALID[/red]")
    )
    root_label = (
        "[green]matches[/green]" if result.root_hash_match else "[red]MISMATCH[/red]"
    )
    console.print()
    console.print(
        Panel(
            f"[bold {color}]{'✅ Snapshot INTACT' if result.is_valid else '🚨 TAMPERING DETECTED'}[/bold {color}]\n\n"
            f"[bold]Snapshot:[/bold]   {result.snapshot_id[:24]}\n"
            f"[bold]Root hash:[/bold]  {root_label}\n"
            f"[bold]Signature:[/bold]  {sig_label}\n"
            f"[bold]Tampered:[/bold]   [red]{len(result.tampered_ids)}[/red]",
            title="🧠 Vault Integrity",
            border_style=color,
        )
    )
    if result.tampered_ids:
        console.print("[bold red]Tampered entries[/bold red]")
        for eid in result.tampered_ids[:20]:
            console.print(f"  [red]✗[/red] {eid}")
        if len(result.tampered_ids) > 20:
            console.print(f"  [dim]… and {len(result.tampered_ids) - 20} more[/dim]")
    console.print()
    raise SystemExit(0 if result.is_valid else 2)


@memory_group.command("rollback")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("snapshot_id")
@click.option(
    "--apply",
    "apply_changes",
    is_flag=True,
    help="Actually apply the rollback (default: plan only)",
)
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip interactive confirmation when --apply is set",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_rollback(
    vault_path: str,
    snapshot_id: str,
    apply_changes: bool,
    yes: bool,
    output_json: bool,
) -> None:
    """
    Build a rollback plan to a target snapshot. Use --apply to commit.

    Without --apply, the command prints what *would* change but makes no
    modifications. This is the recommended forensic workflow: review the
    plan, confirm it matches the incident timeline, then re-run with --apply.

    \b
    Examples:
        memgar memory rollback ./vault.db 7a3f9b1c          # plan only
        memgar memory rollback ./vault.db 7a3f9b1c --apply  # interactive
        memgar memory rollback ./vault.db 7a3f9b1c --apply -y --json
    """
    vault = _open_vault(vault_path)
    target = _resolve_snapshot(vault, snapshot_id)
    plan = vault.rollback(snapshot_id=target.id)
    delta = plan.diff

    plan_summary = {
        "target_snapshot_id": plan.target_snapshot_id,
        "entries_to_restore": [e.entry_id for e in plan.entries_to_restore],
        "entry_ids_to_delete": plan.entry_ids_to_delete,
        "total_changes": delta.total_changes,
        "applied": False,
    }

    if not apply_changes:
        if output_json:
            console.print_json(json.dumps(plan_summary, indent=2))
            return
        console.print()
        console.print(
            Panel(
                f"[bold]Target snapshot:[/bold] {plan.target_snapshot_id[:24]}\n"
                f"[bold]Would restore:[/bold]   [green]{len(plan.entries_to_restore)}[/green] entries\n"
                f"[bold]Would delete:[/bold]    [red]{len(plan.entry_ids_to_delete)}[/red] entries\n\n"
                f"[dim]This is a PLAN. No changes were made.[/dim]\n"
                f"[dim]Re-run with --apply to commit, or --apply -y to skip confirmation.[/dim]",
                title="🧠 Rollback Plan (preview)",
                border_style="cyan",
            )
        )
        console.print()
        return

    if not yes:
        confirmed = click.confirm(
            f"\nApply rollback to snapshot {plan.target_snapshot_id[:8]}? "
            f"({len(plan.entries_to_restore)} restored, "
            f"{len(plan.entry_ids_to_delete)} deleted)",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Cancelled.[/yellow]")
            raise SystemExit(1)

    plan.confirmed = True
    vault.apply_rollback(plan)
    # Take a new snapshot so the rollback is durable across CLI invocations
    # and visible in subsequent forensics (replay / list).
    new_snap = vault.take_snapshot(
        label=f"rollback-to-{plan.target_snapshot_id[:8]}"
    )
    plan_summary["applied"] = True
    plan_summary["new_snapshot_id"] = new_snap.id

    if output_json:
        console.print_json(json.dumps(plan_summary, indent=2))
        return
    console.print()
    console.print(
        Panel(
            f"[bold green]✅ Rollback applied[/bold green]\n\n"
            f"[bold]Target snapshot:[/bold]   {plan.target_snapshot_id[:24]}\n"
            f"[bold]New snapshot:[/bold]      {new_snap.id[:24]}\n"
            f"[bold]Restored:[/bold]          [green]{len(plan.entries_to_restore)}[/green] entries\n"
            f"[bold]Deleted:[/bold]           [red]{len(plan.entry_ids_to_delete)}[/red] entries",
            title="🧠 Memory Vault Rollback",
            border_style="green",
        )
    )
    console.print()


@memory_group.command("replay")
@click.argument("vault_path", type=click.Path(exists=True))
@click.option(
    "--since",
    default=None,
    help="ISO-8601 timestamp (UTC) — only snapshots taken after this",
)
@click.option(
    "--limit", default=20, type=int, help="Show only the last N snapshots in the trail"
)
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_replay(
    vault_path: str,
    since: Optional[str],
    limit: int,
    output_json: bool,
) -> None:
    """
    Render the snapshot timeline as an ASCII forensic trail.

    For each snapshot, shows the inter-snapshot diff (added/deleted/modified
    relative to the immediately preceding snapshot) — letting you trace when
    a poisoned entry first appeared and how it changed across snapshots.

    \b
    Examples:
        memgar memory replay ./vault.db
        memgar memory replay ./vault.db --since 2026-05-17T00:00:00Z
        memgar memory replay ./vault.db --limit 10 --json
    """
    vault = _open_vault(vault_path)
    with vault._lock:  # noqa: SLF001
        snapshots = list(vault._snapshots)  # noqa: SLF001

    if since:
        from datetime import datetime
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            console.print(f"[red]Error:[/red] bad --since format: {exc}")
            raise SystemExit(1)
        since_ts = since_dt.timestamp()
        snapshots = [s for s in snapshots if s.ts >= since_ts]

    snapshots = snapshots[-limit:]

    trail = []
    prev = None
    for snap in snapshots:
        if prev is None:
            trail.append({
                "snapshot_id": snap.id,
                "ts": snap.ts,
                "ts_iso": _format_ts(snap.ts),
                "label": snap.label,
                "entry_count": snap.entry_count,
                "added": list(snap.entries.keys()),
                "deleted": [],
                "modified": [],
            })
        else:
            delta = vault.diff(snapshot_a_id=prev.id, snapshot_b_id=snap.id)
            trail.append({
                "snapshot_id": snap.id,
                "ts": snap.ts,
                "ts_iso": _format_ts(snap.ts),
                "label": snap.label,
                "entry_count": snap.entry_count,
                "added": delta.added,
                "deleted": delta.deleted,
                "modified": [m.entry_id for m in delta.modified],
            })
        prev = snap

    if output_json:
        console.print_json(json.dumps(trail, indent=2))
        return

    if not trail:
        console.print(
            Panel(
                "[yellow]No snapshots match the filter.[/yellow]",
                title="🧠 Memory Replay",
                border_style="yellow",
            )
        )
        return

    console.print()
    console.print(f"[bold cyan]🧠 Memory Replay — {len(trail)} snapshot(s)[/bold cyan]\n")
    for idx, step in enumerate(trail):
        marker = "○" if idx == 0 else "●"
        glyphs = []
        if step["added"]:
            glyphs.append(f"[green]+{len(step['added'])}[/green]")
        if step["deleted"]:
            glyphs.append(f"[red]-{len(step['deleted'])}[/red]")
        if step["modified"]:
            glyphs.append(f"[yellow]~{len(step['modified'])}[/yellow]")
        diff_glyph = "  ".join(glyphs) if glyphs else "[dim]no change[/dim]"
        console.print(
            f"  [cyan]{marker}[/cyan] {step['ts_iso']}  "
            f"[dim]{step['snapshot_id'][:8]}[/dim]  "
            f"{step['label'] or '[dim](unlabeled)[/dim]':<24}  {diff_glyph}"
        )
    console.print()


@memory_group.command("trace")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("entry_id")
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_trace(vault_path: str, entry_id: str, output_json: bool) -> None:
    """
    Trace an entry's provenance across snapshots: first appearance + lineage.

    \b
    Examples:
        memgar memory trace ./vault.db src:evil-doc
        memgar memory trace ./vault.db src:evil-doc --json
    """
    from memgar.replay_forensics import ReplayForensics

    vault = _open_vault(vault_path)
    with vault._lock:  # noqa: SLF001
        snapshots = list(vault._snapshots)  # noqa: SLF001
    forensics = ReplayForensics(snapshots)

    appearance = forensics.first_appearance(entry_id)
    if appearance is None:
        if output_json:
            console.print_json(json.dumps({"entry_id": entry_id, "found": False}))
        else:
            console.print(
                f"[yellow]No occurrences of {entry_id!r} in this vault.[/yellow]"
            )
        raise SystemExit(1)

    lineage = forensics.lineage(entry_id)
    if output_json:
        console.print_json(json.dumps({
            "found": True,
            "appearance": appearance.to_dict(),
            "lineage": [m.to_dict() for m in lineage],
        }, indent=2))
        return

    console.print()
    console.print(
        Panel(
            f"[bold]Entry ID:[/bold]       {appearance.entry_id}\n"
            f"[bold]First seen:[/bold]     {_format_ts(appearance.first_ts)}  "
            f"[dim]{appearance.first_snapshot_id[:8]}[/dim]\n"
            f"[bold]Last seen:[/bold]      {_format_ts(appearance.last_ts)}  "
            f"[dim]{appearance.last_snapshot_id[:8]}[/dim]\n"
            f"[bold]Snapshots seen:[/bold] {appearance.snapshots_seen}\n"
            f"[bold]Lifespan:[/bold]       {appearance.lifespan_seconds:.1f}s\n"
            f"[bold]Mutations:[/bold]      {len(lineage)}",
            title=f"🧠 Memory Trace — {entry_id}",
            border_style="cyan",
        )
    )

    if lineage:
        console.print("[bold cyan]Lineage[/bold cyan]")
        for mut in lineage:
            marker = "[green]●[/green]" if mut.is_first else "[yellow]~[/yellow]"
            console.print(
                f"  {marker} {_format_ts(mut.ts)}  "
                f"[dim]{mut.snapshot_id[:8]}[/dim]  "
                f"[dim]{mut.content_hash[:12]}[/dim]  "
                f"{mut.content_preview[:80]}"
            )
    console.print()


@memory_group.command("cohort")
@click.argument("vault_path", type=click.Path(exists=True))
@click.argument("attr_value")
@click.option(
    "--attr",
    type=click.Choice(["source_id", "source_type"]),
    default="source_id",
    help="Group attribute (default: source_id)",
)
@click.option("--json", "output_json", is_flag=True, help="JSON output")
def memory_cohort(
    vault_path: str,
    attr_value: str,
    attr: str,
    output_json: bool,
) -> None:
    """
    Show every entry that shares an attribute — "what else did this source write?".

    \b
    Examples:
        memgar memory cohort ./vault.db evil-doc
        memgar memory cohort ./vault.db rag --attr source_type
        memgar memory cohort ./vault.db evil-doc --json
    """
    from memgar.replay_forensics import ReplayForensics

    vault = _open_vault(vault_path)
    with vault._lock:  # noqa: SLF001
        snapshots = list(vault._snapshots)  # noqa: SLF001
    forensics = ReplayForensics(snapshots)
    members = forensics.cohort(attr_value, attr=attr)

    if output_json:
        console.print_json(json.dumps({
            "attr": attr,
            "attr_value": attr_value,
            "member_count": len(members),
            "members": [m.to_dict() for m in members],
        }, indent=2))
        return

    if not members:
        console.print(
            Panel(
                f"[yellow]No entries with {attr}={attr_value!r}.[/yellow]",
                title="🧠 Cohort",
                border_style="yellow",
            )
        )
        return

    console.print()
    console.print(
        f"[bold cyan]🧠 Cohort — {attr}={attr_value}  "
        f"({len(members)} entr{'ies' if len(members) != 1 else 'y'})[/bold cyan]\n"
    )
    table = Table(box=box.SIMPLE, show_header=True)
    table.add_column("Entry ID", style="cyan", width=22)
    table.add_column("First seen", width=22)
    table.add_column("Last hash", style="dim", width=14)
    table.add_column("Content (preview)")
    for m in members:
        table.add_row(
            m.entry_id[:20] + ("…" if len(m.entry_id) > 20 else ""),
            _format_ts(m.first_seen_ts),
            m.last_content_hash[:12],
            m.last_content_preview[:80],
        )
    console.print(table)
    console.print()
