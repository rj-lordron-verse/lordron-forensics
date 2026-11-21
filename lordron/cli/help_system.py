"""
Interactive Help System for LORDRON Forensics.
Provides comprehensive command matrices, subcommands, usage examples,
installation guides, and identity details.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from lordron import __author__, __brand__, __version__
from lordron.core.console import console, print_banner


def render_interactive_help() -> None:
    """Render the full interactive /help documentation screen."""
    print_banner(quiet=False)

    title_panel = Panel(
        f"[bold cyan]LORDRON FORENSICS[/bold cyan] [bold white]v{__version__}[/bold white]\n"
        f"[dim]\"Every File Has a Story. Find It.\"\n"
        f"Author: {__author__} | Brand: {__brand__} | License: MIT\n"
        f"Offline-First Digital Investigation Toolkit[/dim]",
        border_style="cyan",
        title="[bold yellow]HELP & DOCUMENTATION SYSTEM[/bold yellow]",
        expand=True,
    )
    console.print(title_panel)

    # 1. Main Commands & Subcommands Table
    t_cmds = Table(
        title="ALL COMMANDS & SUBCOMMANDS REFERENCE",
        border_style="cyan",
        header_style="bold magenta",
        title_style="bold white",
        show_lines=True,
        expand=True,
    )
    t_cmds.add_column("Command / Group", style="bold yellow", no_wrap=True)
    t_cmds.add_column("Subcommand", style="bold green", no_wrap=True)
    t_cmds.add_column("Syntax & Arguments", style="cyan")
    t_cmds.add_column("Description & Investigative Purpose", style="white")

    t_cmds.add_row(
        "file",
        "inspect",
        "lordron file inspect <path>",
        "Inspect true magic byte signature, MIME type, timestamps, and detect malicious extension mismatches."
    )
    t_cmds.add_row(
        "file",
        "batch",
        "lordron file batch <dir> [--recursive]",
        "Batch scan directory for extension anomalies and find duplicate files grouped by SHA256."
    )
    t_cmds.add_row(
        "file",
        "compare",
        "lordron file compare <file1> <file2>",
        "Side-by-side comparison of two files for format, byte size, and cryptographic identity."
    )
    t_cmds.add_row(
        "metadata",
        "inspect",
        "lordron metadata inspect <file> [--exiftool]",
        "Extract EXIF camera hardware, exposure, decoded GPS coordinates, or PDF author/title metadata."
    )
    t_cmds.add_row(
        "metadata",
        "compare",
        "lordron metadata compare <file1> <file2>",
        "Compare embedded metadata properties across two files."
    )
    t_cmds.add_row(
        "hash",
        "calc",
        "lordron hash calc <file> (or 'lordron hash <file>')",
        "Calculate multi-algorithm streaming hashes (SHA256, SHA512, SHA1, and legacy MD5)."
    )
    t_cmds.add_row(
        "hash",
        "verify",
        "lordron hash verify <file> <expected_hash>",
        "Verify file integrity against expected digest with auto-detected algorithm (MD5/SHA1/SHA256/SHA512)."
    )
    t_cmds.add_row(
        "hash",
        "batch",
        "lordron hash batch <dir> [--recursive]",
        "Batch compute SHA256 digests for all files in a directory."
    )
    t_cmds.add_row(
        "case",
        "create",
        "lordron case create <id> [-t title] [-i investigator]",
        "Initialize a new local forensic case and isolated evidence vault in SQLite ledger."
    )
    t_cmds.add_row(
        "case",
        "list",
        "lordron case list [--json]",
        "List all registered forensic cases, titles, status, and evidence counts."
    )
    t_cmds.add_row(
        "case",
        "show",
        "lordron case show <case_id>",
        "Display complete case details, evidence manifest, and chain of custody audit logs."
    )
    t_cmds.add_row(
        "case",
        "add",
        "lordron case add <case_id> <path> [-n notes]",
        "Acquire evidence into vault with read-only permissions (0o444) and record baseline SHA256."
    )
    t_cmds.add_row(
        "case",
        "verify",
        "lordron case verify <case_id>",
        "Audit cryptographic integrity for all evidence items in a case against initial baselines."
    )
    t_cmds.add_row(
        "case",
        "note",
        "lordron case note <case_id> \"note text\" [-a author]",
        "Record an investigator note into the immutable case audit ledger."
    )
    t_cmds.add_row(
        "logs",
        "analyze",
        "lordron logs analyze <file> [-s severity] [--csv path]",
        "Parse syslog/auth.log/web logs, classify severity, detect brute-force anomalies, and export CSV."
    )
    t_cmds.add_row(
        "timeline",
        "(root)",
        "lordron timeline <case_id>",
        "Fuse multi-source chronological timeline distinguishing empirical facts from filesystem times."
    )
    t_cmds.add_row(
        "network",
        "inspect",
        "lordron network inspect <domain>",
        "Passive network inspection: DNS records, TLS certificate, cipher suite, and HTTP headers."
    )
    t_cmds.add_row(
        "network",
        "dns",
        "lordron network dns <domain>",
        "Passive DNS lookup resolving IPv4, IPv6, and reverse PTR hostnames."
    )
    t_cmds.add_row(
        "network",
        "tls",
        "lordron network tls <domain> [-p 443]",
        "Passive TLS handshake inspection measuring handshake latency and cipher details."
    )
    t_cmds.add_row(
        "report",
        "(root)",
        "lordron report <case_id> [-f html|json|csv] [-o path]",
        "Generate comprehensive case reports in responsive HTML, machine JSON, or tabular CSV."
    )
    t_cmds.add_row(
        "doctor",
        "(root)",
        "lordron doctor [--json]",
        "Verify system platform, Python 3.11+, storage, dependencies, and database health."
    )
    t_cmds.add_row(
        "interactive",
        "(root)",
        "lordron interactive (alias: 'lordron menu')",
        "Launch the interactive menu-driven lab environment."
    )
    t_cmds.add_row(
        "demo",
        "(root)",
        "lordron demo [--auto] [--case-id <id>]",
        "Execute an end-to-end simulated investigation walkthrough using bundled evidence artifacts."
    )
    t_cmds.add_row(
        "guide",
        "(root)",
        "lordron guide (alias: 'lordron cheat')",
        "Display the 5 Golden Rules of Forensics, investigation workflows, and cheatsheet."
    )
    t_cmds.add_row(
        "version",
        "(root)",
        "lordron version (or 'lordron -v')",
        "Display version and creator identity."
    )
    console.print(t_cmds)

    # 2. Installation Instructions Panel
    install_text = (
        "[bold cyan]AUTOMATED ONE-STEP INSTALLATION:[/bold cyan]\n"
        "  [bold white]Linux / macOS / Termux (Bash):[/bold white]\n"
        "    [bold green]./install.sh[/bold green]\n"
        "    [bold green]source .venv/bin/activate[/bold green]\n\n"
        "  [bold white]Windows 10/11 (PowerShell):[/bold white]\n"
        "    [bold green]Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass[/bold green]\n"
        "    [bold green].\\install.ps1[/bold green]\n"
        "    [bold green].\\.venv\\Scripts\\Activate.ps1[/bold green]\n\n"
        "[bold cyan]FOR ANDROID TERMUX USERS:[/bold cyan]\n"
        "  [white]1. Install prebuilt binary packages (avoids compiling C/Rust from source):[/white]\n"
        "     [bold green]pkg update && pkg install -y python python-pillow exiftool ruff[/bold green]\n"
        "  [white]2. Run installer inside cloned repository:[/white]\n"
        "     [bold green]./install.sh && source .venv/bin/activate[/bold green]\n\n"
        "[bold cyan]MANUAL VIRTUAL ENVIRONMENT SETUP:[/bold cyan]\n"
        "  [bold green]python3 -m venv .venv[/bold green]          # Windows: python -m venv .venv\n"
        "  [bold green]source .venv/bin/activate[/bold green]      # Windows: .venv\\Scripts\\Activate.ps1\n"
        "  [bold green]pip install -e .[/bold green]\n\n"
        "[bold cyan]VERIFY INSTALLATION:[/bold cyan]\n"
        "  [bold green]lordron doctor[/bold green]                  # Comprehensive platform & health diagnostics\n"
        "  [bold green]lordron version[/bold green]                 # Display brand identity and version"
    )
    console.print(
        Panel(
            install_text,
            border_style="green",
            title="[bold bright_green]INSTALLATION INSTRUCTIONS[/bold bright_green]",
            expand=True,
        )
    )

    # 3. Usage Examples Panel
    examples_text = (
        "[bold yellow]Scenario 1: Triage an unknown downloaded file[/bold yellow]\n"
        "  [cyan]lordron file inspect suspect_invoice.jpg[/cyan]\n"
        "  [dim]-> Detects whether it is actually an executable, PDF, or archive.[/dim]\n\n"
        "[bold yellow]Scenario 2: Calculate and verify file authenticity[/bold yellow]\n"
        "  [cyan]lordron hash calc evidence.raw[/cyan]\n"
        "  [cyan]lordron hash verify evidence.raw 0720f3d332e24b918ec5e3eadb041ca887249ca8c0864230b3e6c456199eb72e[/cyan]\n\n"
        "[bold yellow]Scenario 3: Open an investigation and secure evidence[/bold yellow]\n"
        "  [cyan]lordron case create CASE-2026-001 -t \"Incident Alpha\" -i \"Raj\"[/cyan]\n"
        "  [cyan]lordron case add CASE-2026-001 suspect_invoice.jpg -n \"Recovered from user desktop\"[/cyan]\n"
        "  [cyan]lordron case verify CASE-2026-001[/cyan]\n\n"
        "[bold yellow]Scenario 4: Parse server authentication logs and generate report[/bold yellow]\n"
        "  [cyan]lordron logs analyze /var/log/auth.log --csv auth_summary.csv[/cyan]\n"
        "  [cyan]lordron timeline CASE-2026-001[/cyan]\n"
        "  [cyan]lordron report CASE-2026-001 --format html --output report.html[/cyan]"
    )
    console.print(
        Panel(
            examples_text,
            border_style="yellow",
            title="[bold bright_yellow]PRACTICAL USAGE EXAMPLES[/bold bright_yellow]",
            expand=True,
        )
    )
