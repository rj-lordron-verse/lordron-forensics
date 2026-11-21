"""
Rich console UI and output formatting for LORDRON Forensics.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import sys

# Ensure UTF-8 stream output across Windows (cmd/PowerShell), macOS, and Linux
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Primary console instances
console = Console()
err_console = Console(stderr=True)


def print_banner(quiet: bool = False) -> None:
    """Print the official LORDRON Forensics ASCII brand banner."""
    if quiet:
        return

    banner_text = Text()
    banner_text.append("  _      ____  _____  _____  _____   ____  _   _ \n", style="bold cyan")
    banner_text.append(" | |    / __ \\|  __ \\|  __ \\|  __ \\ / __ \\| \\ | |\n", style="bold cyan")
    banner_text.append(" | |   | |  | | |__) | |  | | |__) | |  | |  \\| |\n", style="bold blue")
    banner_text.append(" | |   | |  | |  _  /| |  | |  _  /| |  | | . ` |\n", style="bold blue")
    banner_text.append(" | |___| |__| | | \\ \\| |__| | | \\ \\| |__| | |\\  |\n", style="bold magenta")
    banner_text.append(" |______\\____/|_|  \\_\\_____/|_|  \\_\\\\____/|_| \\_|\n", style="bold magenta")
    banner_text.append("\n          DIGITAL INVESTIGATION TOOLKIT\n", style="bold white")
    banner_text.append('         "Every File Has a Story. Find It."\n', style="italic bright_yellow")
    banner_text.append("        Version 1.0.0 — Created by Raj | Brand: LORDRON\n", style="dim cyan")

    panel = Panel(
        banner_text,
        border_style="cyan",
        title="[bold red]LORDRON FORENSICS[/bold red]",
        subtitle="[dim green]OFFLINE-FIRST EVIDENCE LAB[/dim green]",
        expand=False,
    )
    console.print(panel)


def print_json_data(data: Any) -> None:
    """Pretty-print structured JSON data to stdout."""
    print(json.dumps(data, indent=2, default=str))


def print_success(msg: Any, quiet: bool = False) -> None:
    if not quiet:
        text = Text()
        text.append("✔ [SUCCESS] ", style="bold green")
        text.append(str(msg))
        console.print(text)


def print_error(msg: Any) -> None:
    text = Text()
    text.append("✘ [ERROR] ", style="bold red")
    text.append(str(msg))
    err_console.print(text)


def print_warning(msg: Any, quiet: bool = False) -> None:
    if not quiet:
        text = Text()
        text.append("▲ [WARNING] ", style="bold yellow")
        text.append(str(msg))
        console.print(text)


def print_info(msg: Any, quiet: bool = False) -> None:
    if not quiet:
        text = Text()
        text.append("ℹ [INFO] ", style="bold cyan")
        text.append(str(msg))
        console.print(text)


def create_table(title: str, columns: list[tuple[str, str]]) -> Table:
    """Helper to create standardized Rich tables."""
    table = Table(title=title, border_style="cyan", header_style="bold magenta")
    for col_name, style in columns:
        table.add_column(col_name, style=style)
    return table
