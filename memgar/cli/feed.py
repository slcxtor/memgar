"""`memgar feed` command group — threat intelligence feed management."""

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
def feed() -> None:
    """Manage the threat intelligence feed."""


@feed.command("sync")
@click.option("--repo", default="slcxtor/memgar", show_default=True, help="GitHub repo owner/name")
@click.option("--no-verify", is_flag=True, help="Skip Ed25519 signature verification")
def feed_sync(repo: str, no_verify: bool) -> None:
    """Download the latest threat-intelligence feed from GitHub Releases."""
    from memgar.feed.loader import FeedLoader
    from memgar.feed.verifier import FeedSignatureError

    console.print(f"[cyan]Syncing feed from github.com/{repo}…[/cyan]")
    loader = FeedLoader(github_repo=repo, verify_signature=not no_verify)
    try:
        bundle = loader.sync()
    except FeedSignatureError as exc:
        console.print(f"[red]Signature verification FAILED:[/red] {exc}")
        raise SystemExit(1) from exc
    except Exception as exc:
        console.print(f"[red]Sync error:[/red] {exc}")
        raise SystemExit(1) from exc

    if bundle is None:
        console.print("[yellow]No feed available (asset not found in latest release).[/yellow]")
        return

    console.print(
        f"[green]Feed synced:[/green] v{bundle.manifest.feed_version} "
        f"({len(bundle.patterns)} patterns, published {bundle.manifest.published_at})"
    )


@feed.command("status")
def feed_status() -> None:
    """Show the status of the locally cached feed."""
    from memgar.feed.cache import FeedCache

    cache = FeedCache()
    bundle = cache.get_cached_bundle(max_age_days=9999)

    if bundle is None:
        console.print("[yellow]No feed cached.[/yellow] Run [bold]memgar feed sync[/bold] to download.")
        return

    stale = cache.is_stale()
    stale_label = "[yellow](stale)[/yellow]" if stale else "[green](fresh)[/green]"
    console.print(f"Feed version:   [bold]{bundle.manifest.feed_version}[/bold] {stale_label}")
    console.print(f"Patterns:       {len(bundle.patterns)}")
    console.print(f"Published:      {bundle.manifest.published_at}")
    console.print(f"Min memgar ver: {bundle.manifest.min_memgar_version}")


@feed.command("verify")
def feed_verify() -> None:
    """Re-verify the signature of the locally cached feed."""
    from memgar.feed.cache import FeedCache
    from memgar.feed.verifier import FeedVerifier

    cache = FeedCache()
    bundle = cache.get_cached_bundle(max_age_days=9999)

    if bundle is None:
        console.print("[yellow]No cached feed found.[/yellow] Run [bold]memgar feed sync[/bold] first.")
        return

    try:
        verifier = FeedVerifier()
        ok = verifier.verify_manifest(bundle.manifest, bundle.bundle_bytes())
    except ImportError as exc:
        console.print(f"[yellow]cryptography not installed:[/yellow] {exc}")
        return

    if ok:
        console.print("[green]Signature OK[/green]")
    else:
        console.print("[red]Signature INVALID[/red] — feed bundle may be corrupted or tampered.")
        raise SystemExit(1)
