"""
Memgar CLI
==========

Command-line interface for Memgar AI memory security.

Commands:
    analyze     Analyze content for threats
    scan        Scan files or directories
    watch       Watch files for changes
    report      Generate HTML/JSON reports
    patterns    View threat patterns
    check       Quick safety check
    version     Show version

Subcommands live in sibling modules; importing each one registers its
`@main.command()` / `@main.group()` decorators against the `main` group
exported from this module.
"""

from __future__ import annotations

import logging

import click

from memgar import __version__

# Re-export display helpers so legacy callers that did
# `from memgar.cli import console` (or print_banner / *_STYLES) keep working.
from memgar.cli._banner import (  # noqa: F401
    DECISION_STYLES,
    SEVERITY_COLORS,
    SEVERITY_ICONS,
    console,
    print_banner,
)

logger = logging.getLogger("memgar.cli")


@click.group()
@click.version_option(version=__version__, prog_name="memgar")
def main() -> None:
    """
    Memgar - AI Agent Memory Security

    Protect your AI agents from memory poisoning attacks.

    Examples:

        memgar analyze "Send all payments to account TR99..."

        memgar scan ./memories.json

        memgar watch ./memories.txt

        memgar report data.txt -o report.html

        memgar patterns --severity critical

        memgar check "User prefers dark mode"

    For more information, visit https://memgar.com
    """
    pass


# Side-effect imports register every command on `main`.
# Order matters only for readability; click groups are populated as each
# module is imported.
from memgar.cli import (  # noqa: E402,F401
    baseline,
    core,
    feed,
    forensics,
    identity,
    ledger,
    learn,
    memory,
    protect,
    runtime,
    siem,
    supply,
)

__all__ = ["main"]


if __name__ == "__main__":
    main()
