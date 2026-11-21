"""
CLI command implementations using Typer and Rich for LORDRON Forensics.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from lordron import __author__, __brand__, __version__
from lordron.cli.dashboard import display_dashboard, render_dashboard_footer
from lordron.cli.demo import run_guided_demo
from lordron.cli.guide import display_forensic_guide
from lordron.cli.help_system import render_interactive_help
from lordron.cli.interactive import (
    interactive_case_manager,
    interactive_file_intelligence,
    interactive_hash_intelligence,
    interactive_log_analyzer,
    interactive_metadata_lab,
    interactive_network_intelligence,
    interactive_report_generator,
    interactive_system_doctor,
    interactive_timeline_engine,
    run_interactive_menu,
)
from lordron.core.console import (
    console,
    print_banner,
    print_error,
    print_info,
    print_json_data,
    print_success,
    print_warning,
)
from lordron.core.exceptions import CaseNotFoundError
from lordron.modules.diagnostics.doctor import run_system_diagnostics
from lordron.modules.evidence_manager.manager import EvidenceManager
from lordron.modules.file_intelligence.inspector import (
    batch_inspect_directory,
    compare_two_files,
    inspect_single_file,
)
from lordron.modules.hash_intelligence.hasher import (
    hash_directory_batch,
    hash_single_file,
    verify_file_integrity,
)
from lordron.modules.log_analyzer.parser import export_log_analysis_csv, parse_log_file
from lordron.modules.metadata_lab.inspector import compare_metadata, inspect_metadata
from lordron.modules.network_intelligence.inspector import (
    full_network_inspection,
    inspect_tls,
    lookup_dns,
)
from lordron.modules.reporting.generator import ReportGenerator
from lordron.modules.timeline.engine import TimelineEngine

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"]}

# Root Typer app
app = typer.Typer(
    name="lordron",
    help="LORDRON Forensics — Open Source Digital Investigation Toolkit.",
    no_args_is_help=False,
    invoke_without_command=True,
    context_settings=CONTEXT_SETTINGS,
)

class HashGroup(typer.core.TyperGroup):
    """Custom TyperGroup to seamlessly route 'lordron hash <file>' directly to calc."""
    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args.insert(0, "calc")
        return super().parse_args(ctx, args)

# Sub-command groups with beginner-friendly no_args_is_help=True and -h support
file_app = typer.Typer(help="Module 01: File format & signature intelligence.", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
metadata_app = typer.Typer(help="Module 02: Metadata extraction (EXIF, GPS, PDF).", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
hash_app = typer.Typer(cls=HashGroup, help="Module 03: Cryptographic hash calculation and verification.", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
case_app = typer.Typer(help="Module 04: Case custody and evidence manager.", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
logs_app = typer.Typer(help="Module 05: Log analyzer and event grouping.", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
network_app = typer.Typer(help="Module 07: Passive network inspection (DNS, TLS, HTTP).", no_args_is_help=True, context_settings=CONTEXT_SETTINGS)

app.add_typer(file_app, name="file")
app.add_typer(metadata_app, name="metadata")
app.add_typer(hash_app, name="hash")
app.add_typer(case_app, name="case")
app.add_typer(logs_app, name="logs")
app.add_typer(network_app, name="network")


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress decorative banners"),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
    version: bool = typer.Option(False, "--version", "-v", help="Show version information"),
    interactive: bool = typer.Option(False, "--interactive", "-i", help="Launch interactive guided mode"),
):
    """Entry callback; displays interactive dashboard when invoked without subcommands."""
    if version:
        typer.echo(f"LORDRON Forensics v{__version__} — Created by {__author__} | Brand: {__brand__}")
        raise typer.Exit()

    if interactive:
        run_interactive_menu()
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        if json_output:
            print_json_data({
                "name": "lordron-forensics",
                "version": __version__,
                "brand": __brand__,
                "author": __author__,
                "status": "ready"
            })
            return

        display_dashboard(quiet=quiet)

        # In interactive terminal sessions, provide quick routing for beginners
        if sys.stdin.isatty() and not quiet:
            console.print(Text("Options: Enter [1-9] for module, [D] for Demo, [G] for Guide, [I] for Interactive Menu, [/help], or [/exit]", style="dim"))
            try:
                choice = Prompt.ask("Your choice [default: I]", default="I").strip()
            except (KeyboardInterrupt, EOFError):
                console.print()
                return

            choice_lower = choice.lower()
            if choice_lower in ["q", "quit", "exit", "/exit", "/quit"]:
                return
            elif choice_lower in ["/help", "help", "/h", "-h", "--help"]:
                render_interactive_help()
                render_dashboard_footer()
            elif choice == "1":
                interactive_file_intelligence()
            elif choice == "2":
                interactive_metadata_lab()
            elif choice == "3":
                interactive_hash_intelligence()
            elif choice == "4":
                interactive_case_manager()
            elif choice == "5":
                interactive_log_analyzer()
            elif choice == "6":
                interactive_timeline_engine()
            elif choice == "7":
                interactive_network_intelligence()
            elif choice == "8":
                interactive_report_generator()
            elif choice == "9":
                interactive_system_doctor()
            elif choice_lower in ["d", "demo"]:
                run_guided_demo(interactive=True)
            elif choice_lower in ["g", "guide", "cheat"]:
                display_forensic_guide()
            elif choice_lower in ["i", "interactive", "menu"]:
                run_interactive_menu()


@app.command(name="help")
def help_command():
    """Display comprehensive LORDRON Forensics help, subcommands, and usage examples."""
    render_interactive_help()
    render_dashboard_footer()


@app.command(name="version")
def show_version():
    """Display LORDRON Forensics version and identity."""
    console.print(
        f"[bold cyan]LORDRON FORENSICS[/bold cyan] "
        f"[bold white]v{__version__}[/bold white]\n"
        f"[dim]Every File Has a Story. Find It.\n"
        f"Created by {__author__} | Brand: {__brand__}[/dim]"
    )


@app.command(name="interactive")
def interactive_command():
    """Launch full guided interactive menu for all forensic modules."""
    run_interactive_menu()


@app.command(name="menu", hidden=True)
def menu_command():
    """Alias for interactive command."""
    run_interactive_menu()


@app.command(name="wizard", hidden=True)
def wizard_command():
    """Alias for interactive command."""
    run_interactive_menu()


@app.command(name="demo")
def demo_command(
    interactive: bool = typer.Option(True, "--interactive/--auto", help="Run interactively with step pauses or automated fast tour"),
    case_id: str | None = typer.Option(None, "--case-id", "-c", help="Custom case identifier for demonstration"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress decorative banners"),
):
    """Run an interactive guided demonstration using simulated forensic evidence."""
    run_guided_demo(interactive=interactive, case_id=case_id, quiet=quiet)


@app.command(name="guide")
def guide_command(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress decorative banners"),
):
    """Display the beginner's forensic manual, standard workflows, and command cheat sheet."""
    display_forensic_guide(quiet=quiet)


@app.command(name="cheat", hidden=True)
def cheat_command(quiet: bool = typer.Option(False, "--quiet", "-q")):
    """Alias for guide command."""
    display_forensic_guide(quiet=quiet)


@app.command(name="quickstart", hidden=True)
def quickstart_command(quiet: bool = typer.Option(False, "--quiet", "-q")):
    """Alias for guide command."""
    display_forensic_guide(quiet=quiet)


@app.command(name="doctor")
def doctor_command(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Run comprehensive system diagnostics, dependencies, and database health check."""
    diag = run_system_diagnostics()

    if json_output:
        print_json_data(diag)
        return

    print_banner(quiet=quiet)
    console.print("[bold cyan]═════ SYSTEM DIAGNOSTICS & READINESS ═════[/bold cyan]\n")

    # System table
    t_sys = Table(title="Host Platform & Runtime", border_style="cyan")
    t_sys.add_column("Property", style="bold white")
    t_sys.add_column("Value", style="yellow")
    for k, v in diag["system"].items():
        t_sys.add_row(k, str(v))
    console.print(t_sys)

    # Dependencies table
    t_dep = Table(title="Dependencies Status", border_style="cyan")
    t_dep.add_column("Library", style="bold white")
    t_dep.add_column("Status", style="yellow")
    for dep, ok in diag["dependencies"].items():
        st = "[bold green]INSTALLED[/bold green]" if ok else "[bold red]MISSING[/bold red]"
        t_dep.add_row(dep, st)
    console.print(t_dep)

    # Optional tools
    t_opt = Table(title="Optional Tools", border_style="cyan")
    t_opt.add_column("Tool", style="bold white")
    t_opt.add_column("Status", style="yellow")
    for opt, ok in diag["optional_tools"].items():
        st = "[bold green]DETECTED[/bold green]" if ok else "[dim yellow]NOT PRESENT[/dim yellow]"
        t_opt.add_row(opt, st)
    console.print(t_opt)

    recs = diag.get("package_recommendations", {})
    if recs:
        t_rec = Table(title="Optional Tools Installation Guide", border_style="cyan")
        t_rec.add_column("Tool", style="bold white")
        t_rec.add_column("Recommended Command", style="cyan")
        for tool_name, cmd in recs.items():
            t_rec.add_row(tool_name, cmd)
        console.print(t_rec)

    # Database
    db = diag["database"]
    st_color = "green" if db["status"] in ["HEALTHY", "NOT_INITIALIZED"] else "red"
    console.print(f"\n[bold white]Database Location:[/bold white] {db['path']}")
    console.print(f"[bold white]Database Status:[/bold white] [{st_color}]{db['status']}[/{st_color}]")

    overall = diag["overall_health"]
    badge_style = "bold green" if overall == "OPTIMAL" else "bold red"
    console.print(f"\n[bold]Overall System Readiness:[/bold] [{badge_style}]{overall}[/{badge_style}]\n")


# ==================================================
# MODULE 01: FILE INTELLIGENCE COMMANDS
# ==================================================
@file_app.command(name="inspect")
def file_inspect(
    path: str = typer.Argument(..., help="Path to file to inspect"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Inspect true file format, signatures, timestamps, and detect extension mismatches."""
    try:
        data = inspect_single_file(path)
        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]File Inspection Report:[/bold cyan] {data['file_name']}\n")

        table = Table(border_style="cyan")
        table.add_column("Property", style="bold magenta", width=25)
        table.add_column("Details", style="white")

        table.add_row("Absolute Path", data["absolute_path"])
        table.add_row("File Size", f"{data['file_size_bytes']:,} bytes")
        table.add_row("Detected Format", f"[bold yellow]{data['detected_format']}[/bold yellow]")
        table.add_row("MIME Type", data["mime_type"])
        table.add_row("SHA256 Digest", f"[bold green]{data['sha256']}[/bold green]")
        table.add_row("Magic Bytes (Hex)", data["header_hex_preview"])
        table.add_row("Modified (UTC)", data["timestamps"]["modified_utc"])
        table.add_row("Metadata Changed (UTC)", data["timestamps"]["created_or_metadata_changed_utc"])

        if data["suspicious_mismatch"]:
            table.add_row("MISMATCH ALERT", f"[bold red]⚠ {data['mismatch_details']}[/bold red]")
        else:
            table.add_row("Signature Match", "[green]✔ File signature aligns with extension[/green]")

        console.print(table)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@file_app.command(name="batch")
def file_batch(
    directory: str = typer.Argument(..., help="Directory path to scan"),
    recursive: bool = typer.Option(True, "--recursive", help="Recursive scan"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Batch scan a directory, detect signature anomalies, and find duplicate files."""
    try:
        data = batch_inspect_directory(directory, recursive=recursive)
        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]Batch Scan Directory:[/bold cyan] {data['directory']}\n")
        console.print(f"Total Files Scanned: [bold white]{data['total_files_scanned']}[/bold white]")
        console.print(f"Extension Mismatches: [bold red]{data['suspicious_mismatches_found']}[/bold red]")
        console.print(f"Duplicate Groups: [bold yellow]{data['duplicate_groups_found']}[/bold yellow]\n")

        if data["suspicious_files"]:
            console.print("[bold red]⚠ Suspicious Extension Mismatches:[/bold red]")
            for s in data["suspicious_files"]:
                console.print(f"  • [red]{s['file_name']}[/red]: {s['mismatch_details']}")
            console.print()

        if data["duplicates"]:
            console.print("[bold yellow]Deduplication Findings (Identical SHA256):[/bold yellow]")
            for h, paths in data["duplicates"].items():
                console.print(f"  [cyan]Hash {h[:16]}... ({len(paths)} copies):[/cyan]")
                for p in paths:
                    console.print(f"    - {p}")
            console.print()

        print_success("Batch inspection complete.", quiet=quiet)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@file_app.command(name="compare")
def file_compare(
    file1: str = typer.Argument(..., help="First file to compare"),
    file2: str = typer.Argument(..., help="Second file to compare"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compare two files side-by-side for format, size, and hash equality."""
    try:
        data = compare_two_files(file1, file2)
        if json_output:
            print_json_data(data)
            return

        t = Table(title="File Comparison", border_style="cyan")
        t.add_column("Attribute", style="bold magenta")
        t.add_column(f"File 1: {data['file1']['file_name']}", style="white")
        t.add_column(f"File 2: {data['file2']['file_name']}", style="white")

        t.add_row("Format", data["file1"]["detected_format"], data["file2"]["detected_format"])
        t.add_row("Size (bytes)", str(data["file1"]["file_size_bytes"]), str(data["file2"]["file_size_bytes"]))
        t.add_row("SHA256", data["file1"]["sha256"][:24] + "...", data["file2"]["sha256"][:24] + "...")
        console.print(t)

        if data["identical_content"]:
            print_success("Files are cryptographically IDENTICAL (Matching SHA256).")
        else:
            print_warning("Files DIFFER in cryptographic content.")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 02: METADATA LAB COMMANDS
# ==================================================
@metadata_app.command(name="inspect")
def metadata_inspect(
    file: str = typer.Argument(..., help="File path to analyze"),
    exiftool: bool = typer.Option(False, "--exiftool", help="Query ExifTool if installed"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Extract embedded EXIF, GPS, camera, and PDF properties."""
    try:
        data = inspect_metadata(file, use_exiftool=exiftool)
        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]Metadata Lab Analysis:[/bold cyan] {data['file_name']}\n")

        if data["format_category"] == "IMAGE":
            dims = data.get("dimensions")
            if dims:
                console.print(f"[bold white]Dimensions:[/bold white] {dims['width']} x {dims['height']}")
            if data.get("camera"):
                console.print(f"[bold white]Camera Hardware:[/bold white] {data['camera']}")
            if data.get("gps") and data["gps"].get("coordinates"):
                coords = data["gps"]["coordinates"]
                console.print(f"[bold green]GPS Coordinates Decoded:[/bold green] {coords}")

            all_tags = data.get("all_exif_tags", {})
            if all_tags:
                t = Table(title="Raw EXIF Tags", border_style="cyan")
                t.add_column("Tag Name", style="bold magenta")
                t.add_column("Value", style="white")
                for k, v in list(all_tags.items())[:20]:
                    t.add_row(str(k), str(v)[:80])
                console.print(t)
            else:
                print_info("No EXIF tags present in this image.")

        elif data["format_category"] == "DOCUMENT_PDF":
            console.print(f"[bold white]PDF Page Count:[/bold white] {data.get('page_count', 'Unknown')}")
            console.print(f"[bold white]Encrypted:[/bold white] {data.get('is_encrypted', False)}")
            props = data.get("properties", {})
            if props:
                t = Table(title="PDF Document Properties", border_style="cyan")
                t.add_column("Property", style="bold magenta")
                t.add_column("Value", style="white")
                for k, v in props.items():
                    t.add_row(k.capitalize(), str(v))
                console.print(t)
        else:
            print_info(data.get("note", "Standard filesystem metadata extracted."))

    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@metadata_app.command(name="compare")
def metadata_compare(
    file1: str = typer.Argument(..., help="First file"),
    file2: str = typer.Argument(..., help="Second file"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Compare metadata between two files side by side."""
    try:
        data = compare_metadata(file1, file2)
        if json_output:
            print_json_data(data)
            return
        console.print(f"[bold cyan]Comparing Metadata between {file1} and {file2}[/bold cyan]")
        console.print(f"Summary: {data['comparison_summary']}")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 03: HASH INTELLIGENCE COMMANDS
# ==================================================
@hash_app.command(name="calc")
def hash_calc(
    file: str = typer.Argument(..., help="File path to hash"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Calculate multi-algorithm hashes (SHA256, SHA512, SHA1, legacy MD5)."""
    try:
        data = hash_single_file(file)
        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]Cryptographic Hashes for:[/bold cyan] {data['file_name']}\n")

        t = Table(border_style="cyan")
        t.add_column("Algorithm", style="bold magenta", width=14)
        t.add_column("Hex Digest", style="bold green")

        for algo, val in data["hashes"].items():
            t.add_row(algo.upper(), val)
        console.print(t)
        console.print(f"[dim italic]{data['note']}[/dim italic]\n")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@hash_app.command(name="batch")
def hash_batch(
    directory: str = typer.Argument(..., help="Directory to hash"),
    recursive: bool = typer.Option(True, "--recursive", help="Recursive scan"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Batch compute SHA256 digests for all files in a directory."""
    try:
        data = hash_directory_batch(directory, recursive=recursive)
        if json_output:
            print_json_data(data)
            return

        t = Table(title=f"Batch Hashes: {data['directory']}", border_style="cyan")
        t.add_column("File Name", style="bold white")
        t.add_column("SHA256", style="green")

        for f in data["files"]:
            t.add_row(f.get("file_name", ""), f.get("hashes", {}).get("sha256", "ERROR"))
        console.print(t)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@hash_app.command(name="verify")
def hash_verify(
    file: str = typer.Argument(..., help="File path to verify"),
    expected_hash: str = typer.Argument(..., help="Expected hex digest (MD5/SHA1/SHA256/SHA512)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify cryptographic file integrity against an expected hash."""
    try:
        res = verify_file_integrity(file, expected_hash)
        if json_output:
            print_json_data(res)
            return

        if res["matched"]:
            print_success(f"INTEGRITY VERIFIED: File matches expected {res['algorithm']} digest!")
        else:
            print_error(
                f"INTEGRITY VERIFICATION FAILED!\n"
                f"Expected:   {res['expected']}\n"
                f"Calculated: {res['calculated']}"
            )
            raise typer.Exit(code=2)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 04: EVIDENCE MANAGER COMMANDS
# ==================================================
@case_app.command(name="create")
def case_create(
    case_id: str = typer.Argument(..., help="Unique case identifier"),
    title: str | None = typer.Option(None, "--title", "-t", help="Case title"),
    investigator: str = typer.Option("Raj", "--investigator", "-i", help="Investigator name"),
    description: str = typer.Option("Digital investigation case", "--desc", "-d", help="Description"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a new local investigation case and evidence vault."""
    try:
        mgr = EvidenceManager()
        case = mgr.create_case(case_id, title=title, investigator=investigator, description=description)
        if json_output:
            print_json_data(case.__dict__)
            return
        print_success(f"Case '{case.case_id}' successfully created. Vault ready.")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@case_app.command(name="list")
def case_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON")
):
    """List all registered forensic cases and evidence counts."""
    try:
        mgr = EvidenceManager()
        cases = mgr.list_cases()
        if json_output:
            print_json_data(cases)
            return

        if not cases:
            print_info("No cases registered yet. Run 'lordron case create <case_id>' to start.")
            return

        t = Table(title="Forensic Cases Ledger", border_style="cyan")
        t.add_column("Case ID", style="bold cyan")
        t.add_column("Title", style="white")
        t.add_column("Investigator", style="yellow")
        t.add_column("Status", style="magenta")
        t.add_column("Evidence Count", justify="center", style="green")
        t.add_column("Created (UTC)", style="dim")

        for c in cases:
            t.add_row(c["case_id"], c["title"], c["investigator"], c["status"], str(c["evidence_count"]), c["created_at_utc"])
        console.print(t)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@case_app.command(name="show")
def case_show(
    case_id: str = typer.Argument(..., help="Case identifier"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON")
):
    """Display comprehensive case details, evidence manifest, and audit logs."""
    try:
        mgr = EvidenceManager()
        details = mgr.get_case_details(case_id)
        if json_output:
            print_json_data(details)
            return

        c = details["case"]
        console.print(f"\n[bold cyan]═══ CASE REPORT: {c.case_id} — {c.title} ═══[/bold cyan]")
        console.print(f"Investigator: [bold yellow]{c.investigator}[/bold yellow] | Status: [green]{c.status}[/green]")
        console.print(f"Created (UTC): [dim]{c.created_at_utc}[/dim]\n")

        # Evidence Table
        t_ev = Table(title="Evidence Items in Custody", border_style="cyan")
        t_ev.add_column("ID", style="bold cyan")
        t_ev.add_column("File Name", style="white")
        t_ev.add_column("Format", style="yellow")
        t_ev.add_column("Acquisition SHA256", style="green")
        t_ev.add_column("Status", style="magenta")

        for item in details["evidence"]:
            t_ev.add_row(item.evidence_id, item.file_name, item.detected_format, item.sha256_at_acquisition[:20] + "...", item.integrity_status)
        console.print(t_ev)

        # Audit Table
        t_aud = Table(title="Audit Trail (Chain of Custody)", border_style="cyan")
        t_aud.add_column("Timestamp (UTC)", style="dim")
        t_aud.add_column("Actor", style="yellow")
        t_aud.add_column("Action", style="bold magenta")
        t_aud.add_column("Details", style="white")

        for a in details["audit_logs"]:
            t_aud.add_row(a.timestamp_utc, a.actor, a.action, a.details)
        console.print(t_aud)
        console.print(f"[dim italic]{details['tamper_notice']}[/dim italic]\n")
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@case_app.command(name="add")
def case_add(
    case_id: str = typer.Argument(..., help="Case identifier"),
    file: str = typer.Argument(..., help="Source file to acquire as evidence"),
    notes: str | None = typer.Option(None, "--notes", "-n", help="Acquisition notes"),
    actor: str = typer.Option("Investigator", "--actor", "-a", help="Actor recording acquisition"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Acquire evidence into case vault, compute cryptographic digests, and preserve read-only."""
    try:
        mgr = EvidenceManager()
        item = mgr.acquire_evidence(case_id, file, actor=actor, notes=notes)
        if json_output:
            print_json_data(item.__dict__)
            return

        print_success(
            f"Evidence acquired successfully!\n"
            f"  Evidence ID:   {item.evidence_id}\n"
            f"  Artifact:      {item.file_name}\n"
            f"  Vault Copy:    {item.vault_path} (Read-only)\n"
            f"  SHA256 Digest: {item.sha256_at_acquisition}"
        )
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@case_app.command(name="verify")
def case_verify(
    case_id: str = typer.Argument(..., help="Case identifier"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Re-verify cryptographic integrity for all evidence items in a case."""
    try:
        mgr = EvidenceManager()
        res = mgr.verify_case_integrity(case_id)
        if json_output:
            print_json_data(res)
            return

        t = Table(title=f"Integrity Audit: Case {case_id}", border_style="cyan")
        t.add_column("Evidence ID", style="bold cyan")
        t.add_column("File Name", style="white")
        t.add_column("Status", style="bold")

        for r in res["results"]:
            st_color = "green" if r["status"] == "INTEGRITY_VERIFIED" else "red"
            t.add_row(r["evidence_id"], r["file_name"], f"[{st_color}]{r['status']}[/{st_color}]")
        console.print(t)

        if res["overall_integrity_passed"]:
            print_success("ALL evidence artifacts passed cryptographic integrity verification.")
        else:
            print_error("INTEGRITY COMPROMISE DETECTED: One or more evidence files failed verification!")
            raise typer.Exit(code=2)
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@case_app.command(name="note")
def case_note(
    case_id: str = typer.Argument(..., help="Case identifier"),
    content: str = typer.Argument(..., help="Note content text"),
    author: str = typer.Option("Raj", "--author", "-a", help="Author of the note"),
):
    """Add an investigator note to the case record."""
    try:
        mgr = EvidenceManager()
        note = mgr.add_case_note(case_id, author=author, content=content)
        print_success(f"Note added to case {case_id} (ID: {note.id}).")
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 05: LOG ANALYZER COMMANDS
# ==================================================
@logs_app.command(name="analyze")
def logs_analyze(
    file: str = typer.Argument(..., help="Path to text log file"),
    min_severity: str = typer.Option("DEBUG", "--min-severity", "-s", help="Minimum severity filter"),
    export_csv: str | None = typer.Option(None, "--csv", help="Save parsed events to CSV file"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Analyze log file, detect timestamps, classify severity, and extract error patterns."""
    try:
        data = parse_log_file(file, min_severity=min_severity)

        if export_csv:
            csv_str = export_log_analysis_csv(data)
            with open(export_csv, "w", encoding="utf-8") as f:
                f.write(csv_str)
            print_success(f"Exported log analysis to '{export_csv}'.")

        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]Log Analysis Report:[/bold cyan] {data['file_name']}\n")
        console.print(f"Total Lines: [bold white]{data['total_lines_processed']}[/bold white]")
        console.print(f"Severity Breakdown: {data['severity_summary']}\n")

        # Anomaly pattern table
        t_pat = Table(title="Detected Anomaly Patterns", border_style="cyan")
        t_pat.add_column("Pattern Type", style="bold magenta")
        t_pat.add_column("Occurrences", style="bold yellow", justify="right")
        for p, count in data["anomaly_patterns_detected"].items():
            t_pat.add_row(p, str(count))
        console.print(t_pat)

        # Top recurring events
        t_rec = Table(title="Top Recurring Event Signatures", border_style="cyan")
        t_rec.add_column("Occurrences", style="bold green", justify="right", width=12)
        t_rec.add_column("Normalized Pattern Template", style="white")
        for r in data["top_recurring_events"]:
            t_rec.add_row(str(r["occurrences"]), r["pattern"])
        console.print(t_rec)

        console.print(f"\n[dim italic]{data['interpretation_disclaimer']}[/dim italic]\n")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 06: TIMELINE ENGINE COMMANDS
# ==================================================
@app.command(name="timeline")
def timeline_command(
    case_id: str = typer.Argument(..., help="Case identifier"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress banner"),
):
    """Aggregate multi-source chronological timeline with source classification."""
    try:
        engine = TimelineEngine()
        data = engine.build_case_timeline(case_id)
        if json_output:
            print_json_data(data)
            return

        print_banner(quiet=quiet)
        console.print(f"[bold cyan]Chronological Timeline for Case:[/bold cyan] {data['case_id']}\n")

        t = Table(border_style="cyan")
        t.add_column("Timestamp (UTC)", style="dim", width=22)
        t.add_column("Source Type", style="bold magenta", width=24)
        t.add_column("Event Summary", style="white")

        for ev in data["events"]:
            warn_str = f"\n[red]⚠ {ev['reliability_warning']}[/red]" if ev["reliability_warning"] else ""
            t.add_row(ev["timestamp_utc"], ev["source_type"], f"{ev['summary']}{warn_str}")
        console.print(t)

        console.print(f"\n[yellow italic]{data['forensic_disclaimer']}[/yellow italic]\n")
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 07: NETWORK INTELLIGENCE COMMANDS
# ==================================================
@network_app.command(name="dns")
def network_dns(
    domain: str = typer.Argument(..., help="Target domain"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Passive DNS resolution (A, AAAA, PTR) for a domain."""
    try:
        res = lookup_dns(domain)
        if json_output:
            print_json_data(res)
            return
        console.print(f"[bold cyan]DNS Records for:[/bold cyan] {res['domain']}")
        console.print(f"IPv4: {res['ipv4_addresses']}")
        console.print(f"IPv6: {res['ipv6_addresses']}")
        console.print(f"Reverse Hostnames: {res['reverse_hostnames']}")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@network_app.command(name="tls")
def network_tls(
    domain: str = typer.Argument(..., help="Target domain"),
    port: int = typer.Option(443, "--port", "-p", help="Port"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Inspect remote TLS certificate, handshake latency, and cipher suite."""
    try:
        res = inspect_tls(domain, port=port)
        if json_output:
            print_json_data(res)
            return
        console.print(f"[bold cyan]TLS Handshake Inspection:[/bold cyan] {res['domain']}:{res['port']}")
        console.print(f"Protocol: {res.get('protocol_version')}")
        console.print(f"Cipher:   {res.get('cipher_suite')} ({res.get('cipher_bits')} bits)")
        console.print(f"Latency:  {res.get('handshake_latency_ms')} ms")
        console.print(f"Status:   {res.get('status')}")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


@network_app.command(name="inspect")
def network_inspect(
    domain: str = typer.Argument(..., help="Target domain"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Perform passive network inspection (DNS, TLS, HTTP headers)."""
    try:
        res = full_network_inspection(domain)
        if json_output:
            print_json_data(res)
            return
        console.print(f"[bold cyan]Passive Network Inspection:[/bold cyan] {domain}\n")
        console.print(f"IP Addresses: {res['dns']['ipv4_addresses']}")
        console.print(f"TLS Protocol: {res['tls'].get('protocol_version')}")
        console.print(f"Web Server:   {res['http'].get('server')}")
        console.print(f"[dim italic]{res['safety_notice']}[/dim italic]")
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)


# ==================================================
# MODULE 08: REPORT GENERATOR COMMAND
# ==================================================
@app.command(name="report")
def report_command(
    case_id: str = typer.Argument(..., help="Case identifier"),
    format: str = typer.Option("html", "--format", "-f", help="Output format: html, json, csv"),
    output: str | None = typer.Option(None, "--output", "-o", help="File path to save the report"),
    json_output: bool = typer.Option(False, "--json", help="Shortcut for --format json"),
):
    """Generate professional case report in HTML, JSON, or CSV format."""
    try:
        fmt = "json" if json_output else format.lower()
        generator = ReportGenerator()
        content = generator.generate_report(case_id, fmt=fmt)

        if output:
            out_path = Path(output).resolve()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            print_success(f"Report successfully saved to: {out_path}")
        else:
            if fmt == "html":
                # Save by default to case folder and notify user
                default_path = Path.home() / ".lordron" / "cases" / case_id / f"report_{case_id}.html"
                default_path.parent.mkdir(parents=True, exist_ok=True)
                with open(default_path, "w", encoding="utf-8") as f:
                    f.write(content)
                print_success(f"HTML Report generated at: {default_path}")
                console.print("[dim]Tip: You can open this file in any web browser.[/dim]")
            else:
                print(content)
    except CaseNotFoundError as exc:
        print_error(str(exc))
        print_info("Tip: Run 'lordron case list' to view registered cases, or 'lordron case create <id>' to create a new one.")
        raise typer.Exit(code=1)
    except Exception as exc:
        print_error(str(exc))
        raise typer.Exit(code=1)
