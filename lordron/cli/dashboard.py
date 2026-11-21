"""
Terminal dashboard and menu presentation for LORDRON Forensics.
"""

from __future__ import annotations
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from lordron.core.console import console, print_banner

MODULES_CATALOG = [
    ("01", "FILE INTELLIGENCE", "lordron file inspect <path>", "Magic byte signatures, MIME types, extension mismatches, deduplication."),
    ("02", "METADATA LAB", "lordron metadata inspect <file>", "EXIF extraction, GPS coordinates mapping, PDF document properties."),
    ("03", "HASH INTELLIGENCE", "lordron hash <file>", "Streaming SHA256/512/SHA1/MD5, batch calculation, integrity verification."),
    ("04", "EVIDENCE MANAGER", "lordron case create <id>", "SQLite case custody, UTC timestamps, read-only preservation, audit trail."),
    ("05", "LOG ANALYZER", "lordron logs analyze <file>", "Syslog, Auth.log, web access logs, error pattern detection, frequency counts."),
    ("06", "TIMELINE ENGINE", "lordron timeline <case_id>", "Multi-source chronological event fusion with source reliability warnings."),
    ("07", "NETWORK INTELLIGENCE", "lordron network inspect <domain>", "Passive DNS, TLS certificate inspection, HTTP security response headers."),
    ("08", "REPORT GENERATOR", "lordron report <case_id>", "Self-contained HTML, machine-readable JSON, and tabular CSV reports."),
    ("09", "SYSTEM DIAGNOSTICS", "lordron doctor", "System diagnostics, Python version, dependencies, and database health check."),
]


def render_dashboard_footer() -> None:
    """
    Render the persistent terminal footer for LORDRON Forensics.
    Ensures clear navigation and commands reference across screen refreshes.
    """
    footer_text = Text()
    footer_text.append("LORDRON FORENSICS | v1.0.0\n", style="bold cyan")
    footer_text.append("/help", style="bold yellow")
    footer_text.append(" for all commands | ", style="white")
    footer_text.append("/exit", style="bold red")
    footer_text.append(" to quit", style="white")

    panel = Panel(
        footer_text,
        border_style="cyan",
        title_align="center",
        expand=True,
    )
    console.print(panel)


def display_dashboard(quiet: bool = False) -> None:
    """Render the official interactive terminal dashboard."""
    print_banner(quiet=quiet)

    table = Table(
        title="FORENSIC MODULES CATALOG",
        border_style="cyan",
        header_style="bold magenta",
        title_style="bold white",
        show_lines=True,
        expand=True,
    )
    table.add_column("No.", style="bold cyan", justify="center", no_wrap=True)
    table.add_column("Module Name", style="bold yellow", no_wrap=True)
    table.add_column("Quick Command", style="bold green")
    table.add_column("Capabilities Overview", style="white")

    for no, name, cmd, desc in MODULES_CATALOG:
        table.add_row(no, name, cmd, desc)

    console.print(table)

    quickstart_panel = Panel(
        "[bold cyan]Quickstart Shortcuts for Beginners:[/bold cyan]\n"
        "  • [bold green]lordron interactive[/bold green] [dim](or 'lordron menu')[/dim]  Launch guided menu interface\n"
        "  • [bold green]lordron demo[/bold green]                         Run hands-on sample case investigation walkthrough\n"
        "  • [bold green]lordron guide[/bold green]                        View forensic principles, workflows & command cheat sheet\n"
        "  • [bold green]lordron doctor[/bold green]                       Run environment diagnostics and verify database health\n"
        "  • [bold green]lordron <module> --help[/bold green]          View detailed command line arguments for any module",
        border_style="bright_blue",
        title="[bold white]BEGINNER ASSISTANCE[/bold white]",
        expand=True,
    )
    console.print(quickstart_panel)

    # Render persistent footer
    render_dashboard_footer()
