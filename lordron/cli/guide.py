"""
Module: Beginner's Forensic Guide and Command Cheat Sheet for LORDRON Forensics.
Provides clear conceptual foundations, standard workflows, and command references.
"""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table

from lordron.core.console import console, print_banner


def display_forensic_guide(topic: str | None = None, quiet: bool = False) -> None:
    """Render the official beginner-friendly forensic guide and cheatsheet."""
    print_banner(quiet=quiet)

    console.print(
        Panel(
            "[bold white]LORDRON FORENSICS — INVESTIGATOR'S FIELD MANUAL & CHEAT SHEET[/bold white]\n"
            "[dim]A foundational reference for ethical investigators, analysts, and students.[/dim]",
            border_style="cyan",
            title="[bold yellow]FIELD MANUAL[/bold yellow]",
            expand=True,
        )
    )

    # 1. Golden Rules
    rules_text = (
        "[bold cyan]1. NEVER ANALYZE ORIGINAL EVIDENCE DIRECTLY[/bold cyan]\n"
        "   Always preserve original files. Create a bit-stream or working copy, place it in a read-only vault "
        "(`0o444`), and calculate baseline hashes before opening or inspecting it.\n\n"
        "[bold cyan]2. FILE EXTENSIONS ARE MERE SUGGESTIONS[/bold cyan]\n"
        "   Attackers and malware regularly rename binaries to `.jpg`, `.pdf`, or `.docx` to bypass casual visual "
        "inspection and primitive filters. Always inspect raw magic bytes (header signatures).\n\n"
        "[bold cyan]3. HASHES ARE UNFORGEABLE DIGITAL FINGERPRINTS[/bold cyan]\n"
        "   A single modified bit completely changes the SHA-256 digest (avalanche effect). Cryptographic digests "
        "establish baseline authenticity in court or incident response.\n\n"
        "[bold cyan]4. DOCUMENT THE CHAIN OF CUSTODY CONTINUOUSLY[/bold cyan]\n"
        "   Record who collected the artifact, when (in standardized UTC), how it was stored, and every analysis action.\n\n"
        "[bold cyan]5. DISTINGUISH EMPIRICAL FACTS FROM INTERPRETATIONS[/bold cyan]\n"
        "   Filesystem `mtime` and `ctime` can be manipulated (timestomping). Vault acquisition hashes and immutable "
        "logs are empirical facts; theories about attacker motive are interpretations."
    )
    console.print(
        Panel(
            rules_text,
            border_style="yellow",
            title="[bold bright_yellow]⚖ THE 5 GOLDEN RULES OF DIGITAL FORENSICS[/bold bright_yellow]",
            expand=True,
        )
    )

    # 2. 5-Phase Workflow
    workflow_table = Table(
        title="STANDARD 5-PHASE INVESTIGATION WORKFLOW",
        border_style="green",
        header_style="bold magenta",
        title_style="bold white",
        show_lines=True,
        expand=True,
    )
    workflow_table.add_column("Phase", style="bold green", no_wrap=True)
    workflow_table.add_column("Investigative Goal", style="bold yellow")
    workflow_table.add_column("LORDRON Command", style="bold cyan")
    workflow_table.add_column("Key Output & Forensic Value", style="white")

    workflow_table.add_row(
        "Phase 1: Triage",
        "Inspect suspect file signatures & detect disguised extensions",
        "lordron file inspect <path>",
        "Identifies true MIME type and flags suspicious extension mismatches."
    )
    workflow_table.add_row(
        "Phase 2: Metadata",
        "Extract embedded EXIF, GPS camera data, or PDF document properties",
        "lordron metadata inspect <file>",
        "Reveals camera model, location coordinates, creator software, and internal timestamps."
    )
    workflow_table.add_row(
        "Phase 3: Custody",
        "Create case ledger and acquire artifact into tamper-evident vault",
        "lordron case create <id>\nlordron case add <id> <path>",
        "Calculates baseline SHA256/512/MD5, stores read-only copy (0444), and logs audit event."
    )
    workflow_table.add_row(
        "Phase 4: Correlation",
        "Parse authentication & system logs for anomalies and failed logins",
        "lordron logs analyze <file>",
        "Categorizes severity, groups recurring patterns, and isolates brute-force attacks."
    )
    workflow_table.add_row(
        "Phase 5: Timeline & Report",
        "Fuse multi-source events chronologically and publish case report",
        "lordron timeline <case_id>\nlordron report <case_id> -f html",
        "Delivers complete, auditable timeline with distinction between facts and filesystem timestamps."
    )
    console.print(workflow_table)

    # 3. Command Cheatsheet Table
    cmd_table = Table(
        title="COMMAND CHEAT SHEET & QUICK REFERENCE",
        border_style="cyan",
        header_style="bold magenta",
        title_style="bold white",
        show_lines=True,
        expand=True,
    )
    cmd_table.add_column("Task Category", style="bold magenta", no_wrap=True)
    cmd_table.add_column("Example Command", style="bold green")
    cmd_table.add_column("What it Does", style="white")

    cmd_table.add_row("Interactive Menu", "lordron interactive", "Launch guided interactive mode with step-by-step prompts")
    cmd_table.add_row("Guided Demo", "lordron demo", "Run a complete simulated investigation using bundled evidence")
    cmd_table.add_row("System Health", "lordron doctor", "Verify environment, Python 3.11+, and SQLite database status")
    cmd_table.add_row("File Triage", "lordron file inspect suspect.jpg", "Detects true magic bytes & extension mismatches")
    cmd_table.add_row("Duplicate Search", "lordron file batch /path/to/dir", "Finds all duplicate files by identical SHA256")
    cmd_table.add_row("File Compare", "lordron file compare file1 file2", "Side-by-side format, size, and hash equality check")
    cmd_table.add_row("Metadata / GPS", "lordron metadata inspect photo.jpg", "Extracts EXIF camera tags and GPS coordinates")
    cmd_table.add_row("Hash Calculation", "lordron hash calc evidence.bin", "Multi-algorithm streaming hash (SHA256, 512, MD5)")
    cmd_table.add_row("Hash Verify", "lordron hash verify evidence.bin <sha256>", "Verifies file integrity against expected digest")
    cmd_table.add_row("New Case", "lordron case create CASE-01 -t 'Phishing'", "Initializes case and dedicated evidence vault")
    cmd_table.add_row("Acquire Evidence", "lordron case add CASE-01 evidence.bin", "Stores read-only copy and records acquisition hash")
    cmd_table.add_row("Verify Custody", "lordron case verify CASE-01", "Re-checks all vault files against baseline hashes")
    cmd_table.add_row("Case Manifest", "lordron case show CASE-01", "Displays evidence items, notes, and full audit trail")
    cmd_table.add_row("Log Analysis", "lordron logs analyze /var/log/auth.log", "Extracts auth failures, sudo uses, and error frequency")
    cmd_table.add_row("Event Timeline", "lordron timeline CASE-01", "Aggregates chronological timeline with reliability warnings")
    cmd_table.add_row("HTML Report", "lordron report CASE-01 -f html", "Compiles standalone HTML report with tables & styling")
    console.print(cmd_table)

    # 4. Forensic Glossary
    glossary_text = (
        "[bold white]Magic Bytes (File Signatures):[/bold white] "
        "The first 2-16 bytes of a file that definitively identify its true format (e.g., `\\x7fELF` for Linux binaries, "
        "`PK\\x03\\x04` for ZIP/DOCX, `%PDF-` for PDFs), independent of filename extension.\n\n"
        "[bold white]SHA-256 (Secure Hash Algorithm 256-bit):[/bold white] "
        "A cryptographic one-way hashing function producing a 64-character hexadecimal digest. Used as the industry "
        "gold standard for evidence integrity verification.\n\n"
        "[bold white]EXIF (Exchangeable Image File Format):[/bold white] "
        "Metadata embedded inside JPEG, TIFF, and PNG images created by cameras and smartphones, including model, exposure, "
        "timestamp, and often latitude/longitude coordinates.\n\n"
        "[bold white]Chain of Custody:[/bold white] "
        "A chronological record that tracks the collection, custody, transfer, analysis, and disposition of physical "
        "and digital evidence to guarantee it has not been altered or replaced.\n\n"
        "[bold white]Timestomping:[/bold white] "
        "An anti-forensics technique where an attacker deliberately modifies filesystem metadata timestamps (`mtime`, `ctime`, `atime`) "
        "to blend into normal operating system files. LORDRON highlights these potential discrepancies."
    )
    console.print(
        Panel(
            glossary_text,
            border_style="magenta",
            title="[bold bright_magenta]📖 KEY FORENSIC TERMS EXPLAINED FOR BEGINNERS[/bold bright_magenta]",
            expand=True,
        )
    )

    console.print(
        "\n[bold green]Ready to practice?[/bold green] Run [cyan]lordron demo[/cyan] to walk through a real simulated case!\n"
    )
