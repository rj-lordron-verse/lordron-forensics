"""
Interactive Guided Mode for LORDRON Forensics.
Provides a beginner-friendly menu-driven environment for all investigation modules.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from lordron.cli.dashboard import render_dashboard_footer
from lordron.cli.demo import run_guided_demo
from lordron.cli.guide import display_forensic_guide
from lordron.cli.help_system import render_interactive_help
from lordron.core.console import (
    console,
    print_banner,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from lordron.core.paths import get_base_dir
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


def prompt_path(
    prompt_text: str,
    default: str | None = None,
    must_exist: bool = True,
    is_dir: bool = False,
) -> Path | None:
    """
    Beginner-friendly path prompter with quote stripping, tilde expansion,
    and helpful retry loops. Type 'b' or 'back' to cancel.
    """
    while True:
        try:
            val = Prompt.ask(prompt_text, default=default or "")
        except (KeyboardInterrupt, EOFError):
            console.print()
            return None

        clean = val.strip().strip("'\"")
        if not clean:
            if default:
                clean = default
            else:
                continue

        if clean.lower() in ["b", "back", "cancel", "q", "exit"]:
            return None

        try:
            p = Path(clean).expanduser().resolve()
        except Exception as exc:
            print_error(f"Invalid path format: {exc}")
            continue

        if must_exist:
            if not p.exists():
                print_error(f"Path does not exist: '{p}'")
                console.print("[dim]Tip: Check for typos, drag-and-drop the file into this terminal, or type 'b' to go back.[/dim]\n")
                continue
            if is_dir and not p.is_dir():
                print_error(f"Path is a file, but a directory was expected: '{p}'")
                continue
            if not is_dir and not p.is_file():
                print_error(f"Path is a directory, but a file was expected: '{p}'")
                continue
            if not os.access(p, os.R_OK):
                print_error(f"Permission denied: Cannot read '{p}'")
                continue

        return p


def prompt_case_id(
    action_prompt: str = "Select a Case",
    allow_create: bool = True,
) -> str | None:
    """
    Interactive case picker. Lists registered cases so beginners
    never have to manually memorize or re-type case IDs.
    """
    mgr = EvidenceManager()
    cases = mgr.list_cases()

    if not cases:
        print_info("No cases registered yet.")
        if allow_create:
            create_now = Confirm.ask("Would you like to create a new case now?", default=True)
            if create_now:
                cid = Prompt.ask("Enter Case ID (e.g. CASE-2026-001)")
                if cid.strip():
                    title = Prompt.ask("Enter Case Title", default=f"Investigation {cid}")
                    inv = Prompt.ask("Investigator Name", default="Investigator")
                    case = mgr.create_case(cid.strip(), title=title, investigator=inv)
                    print_success(f"Case '{case.case_id}' created successfully!")
                    return case.case_id
        return None

    console.print(f"\n[bold cyan]═══ {action_prompt} ═══[/bold cyan]")
    t = Table(border_style="cyan")
    t.add_column("No.", style="bold cyan", width=4, justify="center")
    t.add_column("Case ID", style="bold yellow")
    t.add_column("Title", style="white")
    t.add_column("Evidence Count", justify="center", style="green")
    t.add_column("Status", style="magenta")

    for idx, c in enumerate(cases, start=1):
        t.add_row(str(idx), c["case_id"], c["title"], str(c["evidence_count"]), c["status"])
    console.print(t)

    console.print(Text("Options: Enter [No.] or [Case ID], [N] to create a new case, or [B] to go back", style="dim"))
    choice = Prompt.ask("Your selection", default="1")
    choice_clean = choice.strip()

    if choice_clean.lower() in ["b", "back", "cancel", "q"]:
        return None

    if choice_clean.lower() in ["n", "new"]:
        cid = Prompt.ask("Enter New Case ID")
        if cid.strip():
            title = Prompt.ask("Enter Case Title", default=f"Case {cid}")
            inv = Prompt.ask("Investigator Name", default="Investigator")
            case = mgr.create_case(cid.strip(), title=title, investigator=inv)
            print_success(f"Case '{case.case_id}' created successfully!")
            return case.case_id
        return None

    # Check if number selected
    if choice_clean.isdigit():
        num = int(choice_clean)
        if 1 <= num <= len(cases):
            return cases[num - 1]["case_id"]

    # Check if exact case_id typed
    for c in cases:
        if c["case_id"].lower() == choice_clean.lower():
            return c["case_id"]

    print_warning(f"Unrecognized selection '{choice_clean}'. Returning to menu.")
    return None


def _pause() -> None:
    """Prompt user to press enter before refreshing menu."""
    render_dashboard_footer()
    if sys.stdin.isatty():
        try:
            Prompt.ask(Text("\nPress Enter to return to menu (or /help, /exit)...", style="dim"), default="")
        except (KeyboardInterrupt, EOFError):
            console.print()


def interactive_file_intelligence() -> None:
    """Interactive submenu for Module 01: File Intelligence."""
    while True:
        console.print("\n[bold cyan]─── MODULE 01: FILE INTELLIGENCE ───[/bold cyan]")
        console.print("[1] Inspect Single File (Detect True Format & Extension Mismatches)")
        console.print("[2] Batch Scan Directory (Find Disguises & Duplicate Files)")
        console.print("[3] Compare Two Files (Format, Size & Cryptographic Equality)")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "2", "3", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        if opt == "1":
            p = prompt_path("Enter file path to inspect (or drag & drop here)")
            if p:
                try:
                    data = inspect_single_file(p)
                    t = Table(title=f"File Inspection: {data['file_name']}", border_style="cyan")
                    t.add_column("Property", style="bold magenta", width=25)
                    t.add_column("Details", style="white")
                    t.add_row("Detected Format", f"[bold yellow]{data['detected_format']}[/bold yellow]")
                    t.add_row("MIME Type", data["mime_type"])
                    t.add_row("File Size", f"{data['file_size_bytes']:,} bytes")
                    t.add_row("SHA256", f"[bold green]{data['sha256']}[/bold green]")
                    t.add_row("Magic Bytes (Hex)", data["header_hex_preview"])
                    if data["suspicious_mismatch"]:
                        t.add_row("MISMATCH ALERT", f"[bold red]⚠ {data['mismatch_details']}[/bold red]")
                    else:
                        t.add_row("Extension Check", "[green]✔ File signature aligns with extension[/green]")
                    console.print(t)
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "2":
            p = prompt_path("Enter directory path to scan", is_dir=True)
            if p:
                try:
                    rec = Confirm.ask("Scan subdirectories recursively?", default=True)
                    data = batch_inspect_directory(p, recursive=rec)
                    console.print(f"\nTotal Files Scanned: [bold white]{data['total_files_scanned']}[/bold white]")
                    console.print(f"Extension Mismatches: [bold red]{data['suspicious_mismatches_found']}[/bold red]")
                    console.print(f"Duplicate Groups: [bold yellow]{data['duplicate_groups_found']}[/bold yellow]\n")

                    if data["suspicious_files"]:
                        console.print("[bold red]⚠ Disguised / Suspicious Files:[/bold red]")
                        for s in data["suspicious_files"]:
                            console.print(f"  • {s['file_name']}: {s['mismatch_details']}")

                    if data["duplicates"]:
                        console.print("\n[bold yellow]Duplicate Files (Identical SHA-256):[/bold yellow]")
                        for h, files in data["duplicates"].items():
                            console.print(f"  Hash {h[:16]}... ({len(files)} copies):")
                            for f in files:
                                console.print(f"    - {f}")
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "3":
            p1 = prompt_path("Enter First file path")
            if not p1:
                continue
            p2 = prompt_path("Enter Second file path")
            if not p2:
                continue
            try:
                data = compare_two_files(p1, p2)
                t = Table(title="File Comparison", border_style="cyan")
                t.add_column("Attribute", style="bold magenta")
                t.add_column(f"File 1: {data['file1']['file_name']}", style="white")
                t.add_column(f"File 2: {data['file2']['file_name']}", style="white")
                t.add_row("Format", data["file1"]["detected_format"], data["file2"]["detected_format"])
                t.add_row("Size (bytes)", str(data["file1"]["file_size_bytes"]), str(data["file2"]["file_size_bytes"]))
                t.add_row("SHA256", data["file1"]["sha256"][:24] + "...", data["file2"]["sha256"][:24] + "...")
                console.print(t)
                if data["identical_content"]:
                    print_success("Files are cryptographically IDENTICAL (Matching SHA-256).")
                else:
                    print_warning("Files DIFFER in cryptographic content.")
            except Exception as exc:
                print_error(str(exc))
            _pause()


def interactive_metadata_lab() -> None:
    """Interactive submenu for Module 02: Metadata Lab."""
    while True:
        console.print("\n[bold cyan]─── MODULE 02: METADATA LAB ───[/bold cyan]")
        console.print("[1] Inspect Metadata (Images: EXIF/GPS | PDFs: Properties/Author)")
        console.print("[2] Compare Metadata between Two Files")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "2", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        if opt == "1":
            p = prompt_path("Enter file path (JPEG, PNG, TIFF, or PDF)")
            if p:
                try:
                    data = inspect_metadata(p)
                    cat = data.get("format_category")
                    console.print(f"\n[bold cyan]File:[/bold cyan] {data['file_name']} | Format: [bold yellow]{cat}[/bold yellow]")

                    if cat == "IMAGE":
                        dims = data.get("dimensions")
                        if dims:
                            console.print(f"Dimensions: {dims['width']} x {dims['height']}")
                        if data.get("camera"):
                            console.print(f"Camera Hardware: {data['camera']}")
                        if data.get("gps") and data["gps"].get("coordinates"):
                            coords = data["gps"]["coordinates"]
                            console.print(f"[bold green]GPS Decoded:[/bold green] {coords}")
                        tags = data.get("all_exif_tags", {})
                        if tags:
                            t = Table(title="EXIF Tags", border_style="cyan")
                            t.add_column("Tag Name", style="bold magenta")
                            t.add_column("Value", style="white")
                            for k, v in list(tags.items())[:25]:
                                t.add_row(str(k), str(v)[:80])
                            console.print(t)
                        else:
                            print_info("No EXIF metadata tags embedded in this image.")

                    elif cat == "DOCUMENT_PDF":
                        console.print(f"Pages: {data.get('page_count')} | Encrypted: {data.get('is_encrypted')}")
                        props = data.get("properties", {})
                        if props:
                            t = Table(title="PDF Document Properties", border_style="cyan")
                            t.add_column("Property", style="bold magenta")
                            t.add_column("Value", style="white")
                            for k, v in props.items():
                                t.add_row(k.capitalize(), str(v))
                            console.print(t)
                    else:
                        print_info(data.get("note", "Filesystem metadata available."))
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "2":
            p1 = prompt_path("Enter First file path")
            if not p1:
                continue
            p2 = prompt_path("Enter Second file path")
            if not p2:
                continue
            try:
                data = compare_metadata(p1, p2)
                console.print("\n[bold cyan]Metadata Comparison Summary:[/bold cyan]")
                for k, v in data["comparison_summary"].items():
                    console.print(f"  {k}: [yellow]{v}[/yellow]")
            except Exception as exc:
                print_error(str(exc))
            _pause()


def interactive_hash_intelligence() -> None:
    """Interactive submenu for Module 03: Hash Intelligence."""
    while True:
        console.print("\n[bold cyan]─── MODULE 03: HASH INTELLIGENCE ───[/bold cyan]")
        console.print("[1] Calculate Multi-Algorithm Hashes (SHA256, SHA512, SHA1, MD5)")
        console.print("[2] Verify File Integrity against Expected Hash")
        console.print("[3] Batch Hash All Files in Directory")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "2", "3", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        if opt == "1":
            p = prompt_path("Enter file path to hash")
            if p:
                try:
                    data = hash_single_file(p)
                    t = Table(title=f"Cryptographic Digests: {data['file_name']}", border_style="cyan")
                    t.add_column("Algorithm", style="bold magenta", width=14)
                    t.add_column("Digest", style="bold green")
                    for algo, digest in data["hashes"].items():
                        t.add_row(algo.upper(), digest)
                    console.print(t)
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "2":
            p = prompt_path("Enter file path to verify")
            if not p:
                continue
            exp = Prompt.ask("Enter expected hash (MD5, SHA1, SHA256, or SHA512)").strip().lower()
            try:
                res = verify_file_integrity(p, exp)
                if res["matched"]:
                    print_success(f"INTEGRITY VERIFIED: File matches expected {res['algorithm']} digest!")
                else:
                    print_error(
                        f"INTEGRITY VERIFICATION FAILED!\n"
                        f"Expected:   {res['expected']}\n"
                        f"Calculated: {res['calculated']}"
                    )
            except Exception as exc:
                print_error(str(exc))
            _pause()

        elif opt == "3":
            p = prompt_path("Enter directory path to hash", is_dir=True)
            if p:
                try:
                    rec = Confirm.ask("Include subdirectories recursively?", default=True)
                    data = hash_directory_batch(p, recursive=rec)
                    t = Table(title=f"Batch Hashes: {data['directory']}", border_style="cyan")
                    t.add_column("File Name", style="bold white")
                    t.add_column("SHA256 Digest", style="green")
                    for f in data["files"][:50]:
                        t.add_row(f.get("file_name", ""), f.get("hashes", {}).get("sha256", "ERROR"))
                    console.print(t)
                    if len(data["files"]) > 50:
                        console.print(f"[dim]... and {len(data['files']) - 50} more files.[/dim]")
                except Exception as exc:
                    print_error(str(exc))
                _pause()


def interactive_case_manager() -> None:
    """Interactive submenu for Module 04: Case & Evidence Manager."""
    mgr = EvidenceManager()
    while True:
        console.print("\n[bold cyan]─── MODULE 04: CASE & EVIDENCE CUSTODY ───[/bold cyan]")
        console.print("[1] List All Registered Cases")
        console.print("[2] Create a New Forensic Case")
        console.print("[3] Show Case Manifest & Chain of Custody Audit Trail")
        console.print("[4] Acquire Evidence into Case Vault (0o444 Read-Only Preservation)")
        console.print("[5] Verify Case Cryptographic Integrity")
        console.print("[6] Add Investigator Case Note")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        if opt == "1":
            cases = mgr.list_cases()
            if not cases:
                print_info("No cases registered yet.")
            else:
                t = Table(title="Forensic Cases Ledger", border_style="cyan")
                t.add_column("Case ID", style="bold cyan")
                t.add_column("Title", style="white")
                t.add_column("Investigator", style="yellow")
                t.add_column("Status", style="magenta")
                t.add_column("Evidence", justify="center", style="green")
                t.add_column("Created (UTC)", style="dim")
                for c in cases:
                    t.add_row(c["case_id"], c["title"], c["investigator"], c["status"], str(c["evidence_count"]), c["created_at_utc"])
                console.print(t)
            _pause()

        elif opt == "2":
            cid = Prompt.ask("Enter unique Case ID (e.g. CASE-2026-001)").strip()
            if not cid:
                continue
            title = Prompt.ask("Case Title", default=f"Investigation {cid}")
            inv = Prompt.ask("Lead Investigator", default="Raj")
            desc = Prompt.ask("Case Description", default="Digital forensic examination")
            try:
                case = mgr.create_case(cid, title=title, investigator=inv, description=desc)
                print_success(f"Case '{case.case_id}' successfully created. Vault ready.")
            except Exception as exc:
                print_error(str(exc))
            _pause()

        elif opt == "3":
            cid = prompt_case_id("Select Case to Inspect")
            if cid:
                try:
                    details = mgr.get_case_details(cid)
                    c = details["case"]
                    console.print(f"\n[bold cyan]═══ CASE REPORT: {c.case_id} — {c.title} ═══[/bold cyan]")
                    console.print(f"Investigator: [bold yellow]{c.investigator}[/bold yellow] | Status: [green]{c.status}[/green]")

                    t_ev = Table(title="Evidence in Custody", border_style="cyan")
                    t_ev.add_column("ID", style="bold cyan")
                    t_ev.add_column("File Name", style="white")
                    t_ev.add_column("Format", style="yellow")
                    t_ev.add_column("Acquisition SHA256", style="green")
                    t_ev.add_column("Status", style="magenta")
                    for item in details["evidence"]:
                        t_ev.add_row(item.evidence_id, item.file_name, item.detected_format, item.sha256_at_acquisition[:20] + "...", item.integrity_status)
                    console.print(t_ev)

                    t_aud = Table(title="Audit Trail (Chain of Custody)", border_style="cyan")
                    t_aud.add_column("Timestamp (UTC)", style="dim")
                    t_aud.add_column("Actor", style="yellow")
                    t_aud.add_column("Action", style="bold magenta")
                    t_aud.add_column("Details", style="white")
                    for a in details["audit_logs"]:
                        t_aud.add_row(a.timestamp_utc, a.actor, a.action, a.details)
                    console.print(t_aud)
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "4":
            cid = prompt_case_id("Select Case for Evidence Acquisition")
            if not cid:
                continue
            src = prompt_path("Enter file path to acquire into vault")
            if not src:
                continue
            notes = Prompt.ask("Acquisition Notes (e.g. source, location, physical condition)", default="Acquired during triage")
            try:
                item = mgr.acquire_evidence(cid, src, actor="Investigator", notes=notes)
                print_success(
                    f"Evidence acquired successfully!\n"
                    f"  Evidence ID:   {item.evidence_id}\n"
                    f"  Artifact:      {item.file_name}\n"
                    f"  Vault Copy:    {item.vault_path} (0o444 Read-only)\n"
                    f"  SHA256 Digest: {item.sha256_at_acquisition}"
                )
            except Exception as exc:
                print_error(str(exc))
            _pause()

        elif opt == "5":
            cid = prompt_case_id("Select Case for Integrity Verification")
            if cid:
                try:
                    res = mgr.verify_case_integrity(cid)
                    t = Table(title=f"Integrity Audit: Case {cid}", border_style="cyan")
                    t.add_column("Evidence ID", style="bold cyan")
                    t.add_column("File Name", style="white")
                    t.add_column("Status", style="bold")
                    for r in res["results"]:
                        st_col = "green" if r["status"] == "INTEGRITY_VERIFIED" else "red"
                        t.add_row(r["evidence_id"], r["file_name"], f"[{st_col}]{r['status']}[/{st_col}]")
                    console.print(t)
                    if res["overall_integrity_passed"]:
                        print_success("ALL evidence artifacts passed cryptographic integrity verification.")
                    else:
                        print_error("INTEGRITY COMPROMISE DETECTED: One or more evidence files failed verification!")
                except Exception as exc:
                    print_error(str(exc))
                _pause()

        elif opt == "6":
            cid = prompt_case_id("Select Case to Add Note")
            if cid:
                content = Prompt.ask("Enter Case Note text")
                author = Prompt.ask("Author Name", default="Raj")
                try:
                    note = mgr.add_case_note(cid, author=author, content=content)
                    print_success(f"Note recorded (ID: {note.id}) for case {cid}.")
                except Exception as exc:
                    print_error(str(exc))
                _pause()


def interactive_log_analyzer() -> None:
    """Interactive submenu for Module 05: Log Analyzer."""
    while True:
        console.print("\n[bold cyan]─── MODULE 05: LOG ANALYZER ───[/bold cyan]")
        console.print("[1] Analyze Text Log File (Syslog, Auth.log, Web logs)")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        if opt == "1":
            p = prompt_path("Enter log file path to analyze")
            if p:
                min_sev = Prompt.ask("Minimum severity filter", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], default="DEBUG")
                do_csv = Confirm.ask("Export parsed results to a CSV file?", default=False)
                csv_path = None
                if do_csv:
                    csv_path = Prompt.ask("Enter output CSV path", default=f"{p.stem}_analysis.csv")

                try:
                    data = parse_log_file(p, min_severity=min_sev)
                    if csv_path:
                        csv_str = export_log_analysis_csv(data)
                        with open(csv_path, "w", encoding="utf-8") as f:
                            f.write(csv_str)
                        print_success(f"Exported CSV analysis to '{csv_path}'.")

                    console.print(f"\n[bold cyan]Log Analysis Report:[/bold cyan] {data['file_name']}")
                    console.print(f"Total Lines: [bold white]{data['total_lines_processed']}[/bold white]")
                    console.print(f"Severity Distribution: [bold yellow]{data['severity_summary']}[/bold yellow]\n")

                    t_pat = Table(title="Detected Anomaly Patterns", border_style="cyan")
                    t_pat.add_column("Pattern Type", style="bold magenta")
                    t_pat.add_column("Occurrences", style="bold yellow", justify="right")
                    for k, v in data["anomaly_patterns_detected"].items():
                        t_pat.add_row(k, str(v))
                    console.print(t_pat)

                    t_rec = Table(title="Top Recurring Signatures", border_style="cyan")
                    t_rec.add_column("Count", style="bold green", justify="right", width=8)
                    t_rec.add_column("Pattern Template", style="white")
                    for r in data["top_recurring_events"][:8]:
                        t_rec.add_row(str(r["occurrences"]), r["pattern"])
                    console.print(t_rec)
                except Exception as exc:
                    print_error(str(exc))
                _pause()


def interactive_timeline_engine() -> None:
    """Interactive submenu for Module 06: Timeline Engine."""
    cid = prompt_case_id("Select Case to Generate Multi-Source Timeline")
    if cid:
        try:
            engine = TimelineEngine()
            data = engine.build_case_timeline(cid)
            console.print(f"\n[bold cyan]Chronological Timeline for Case:[/bold cyan] {data['case_id']}\n")

            t = Table(border_style="cyan")
            t.add_column("Timestamp (UTC)", style="dim", width=22)
            t.add_column("Source Type", style="bold magenta", width=24)
            t.add_column("Event Summary", style="white")

            for ev in data["events"]:
                warn = f"\n[red]⚠ {ev['reliability_warning']}[/red]" if ev["reliability_warning"] else ""
                t.add_row(ev["timestamp_utc"], ev["source_type"], f"{ev['summary']}{warn}")
            console.print(t)
            console.print(f"\n[dim italic]{data['forensic_disclaimer']}[/dim italic]")
        except Exception as exc:
            print_error(str(exc))
        _pause()


def interactive_network_intelligence() -> None:
    """Interactive submenu for Module 07: Network Intelligence."""
    while True:
        console.print("\n[bold cyan]─── MODULE 07: PASSIVE NETWORK INTELLIGENCE ───[/bold cyan]")
        console.print("[1] Full Passive Inspection (DNS + TLS + HTTP Security Headers)")
        console.print("[2] Passive DNS Resolution (A, AAAA, PTR)")
        console.print("[3] Inspect TLS Handshake & Certificate")
        console.print("[B] Back to Main Menu")

        opt = Prompt.ask("Select option", choices=["1", "2", "3", "b", "B"], default="1")
        if opt.lower() == "b":
            break

        domain = Prompt.ask("Enter target domain or hostname (e.g. example.com)").strip()
        if not domain or domain.lower() in ["b", "back"]:
            continue

        try:
            if opt == "1":
                res = full_network_inspection(domain)
                console.print(f"\n[bold cyan]Network Inspection:[/bold cyan] {domain}")
                console.print(f"IPv4 Addresses: {res['dns']['ipv4_addresses']}")
                console.print(f"TLS Protocol:   {res['tls'].get('protocol_version')}")
                console.print(f"Web Server:     {res['http'].get('server')}")
                console.print(f"[dim italic]{res['safety_notice']}[/dim italic]")
            elif opt == "2":
                res = lookup_dns(domain)
                console.print(f"\n[bold cyan]DNS Records for:[/bold cyan] {res['domain']}")
                console.print(f"IPv4: {res['ipv4_addresses']}")
                console.print(f"IPv6: {res['ipv6_addresses']}")
                console.print(f"Reverse Hostnames: {res['reverse_hostnames']}")
            elif opt == "3":
                res = inspect_tls(domain)
                console.print(f"\n[bold cyan]TLS Handshake:[/bold cyan] {res['domain']}:{res['port']}")
                console.print(f"Protocol: {res.get('protocol_version')}")
                console.print(f"Cipher:   {res.get('cipher_suite')} ({res.get('cipher_bits')} bits)")
                console.print(f"Latency:  {res.get('handshake_latency_ms')} ms")
        except Exception as exc:
            print_error(str(exc))
        _pause()


def interactive_report_generator() -> None:
    """Interactive submenu for Module 08: Report Generator."""
    cid = prompt_case_id("Select Case for Report Generation")
    if cid:
        fmt = Prompt.ask("Select output format", choices=["html", "json", "csv"], default="html")
        custom_out = Confirm.ask("Specify custom output file path?", default=False)
        out_path = None
        if custom_out:
            out_path = Prompt.ask("Output file path")

        try:
            generator = ReportGenerator()
            content = generator.generate_report(cid, fmt=fmt)

            if out_path:
                target = Path(out_path).resolve()
            else:
                target = get_base_dir() / "cases" / cid / f"report_{cid}.{fmt}"

            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "w", encoding="utf-8") as f:
                f.write(content)
            print_success(f"Report successfully saved to: {target}")
            if fmt == "html":
                console.print("[dim]Tip: You can open this HTML report in any web browser to view the formatted case dossier.[/dim]")
        except Exception as exc:
            print_error(str(exc))
        _pause()


def interactive_system_doctor() -> None:
    """Run system diagnostics from the interactive menu."""
    diag = run_system_diagnostics()
    console.print("\n[bold cyan]═════ SYSTEM DIAGNOSTICS & READINESS ═════[/bold cyan]\n")

    t_sys = Table(title="Host Platform & Runtime", border_style="cyan")
    t_sys.add_column("Property", style="bold white")
    t_sys.add_column("Value", style="yellow")
    for k, v in diag["system"].items():
        t_sys.add_row(k, str(v))
    console.print(t_sys)

    t_dep = Table(title="Dependencies Status", border_style="cyan")
    t_dep.add_column("Library", style="bold white")
    t_dep.add_column("Status", style="yellow")
    for dep, ok in diag["dependencies"].items():
        st = "[bold green]INSTALLED[/bold green]" if ok else "[bold red]MISSING[/bold red]"
        t_dep.add_row(dep, st)
    console.print(t_dep)

    db = diag["database"]
    st_color = "green" if db["status"] in ["HEALTHY", "NOT_INITIALIZED"] else "red"
    console.print(f"\n[bold white]Database Location:[/bold white] {db['path']}")
    console.print(f"[bold white]Database Status:[/bold white] [{st_color}]{db['status']}[/{st_color}]")

    overall = diag["overall_health"]
    badge_style = "bold green" if overall == "OPTIMAL" else "bold red"
    console.print(f"\n[bold]Overall System Readiness:[/bold] [{badge_style}]{overall}[/{badge_style}]\n")
    _pause()


def run_interactive_menu() -> None:
    """Launch the main interactive menu loop for LORDRON Forensics."""
    while True:
        print_banner(quiet=False)

        menu_text = (
            "[bold white]Select an Investigation Module or Action:[/bold white]\n\n"
            "  [bold yellow][1][/bold yellow] [bold cyan]File Intelligence[/bold cyan]       — Magic bytes, MIME types, disguises & deduplication\n"
            "  [bold yellow][2][/bold yellow] [bold cyan]Metadata Lab[/bold cyan]            — Embedded EXIF, GPS camera data & PDF properties\n"
            "  [bold yellow][3][/bold yellow] [bold cyan]Hash Intelligence[/bold cyan]       — Streaming SHA256/512/MD5 calculation & integrity verification\n"
            "  [bold yellow][4][/bold yellow] [bold cyan]Evidence & Cases[/bold cyan]        — Case ledger, read-only vault (0o444) & chain of custody\n"
            "  [bold yellow][5][/bold yellow] [bold cyan]Log Analyzer[/bold cyan]            — Anomaly detection, authentication failures & CSV export\n"
            "  [bold yellow][6][/bold yellow] [bold cyan]Timeline Engine[/bold cyan]         — Chronological multi-source fusion with reliability warnings\n"
            "  [bold yellow][7][/bold yellow] [bold cyan]Network Intelligence[/bold cyan]    — Passive DNS, TLS certificate & HTTP security headers\n"
            "  [bold yellow][8][/bold yellow] [bold cyan]Report Generator[/bold cyan]        — Produce standalone HTML, JSON, and CSV investigation dossiers\n"
            "  [bold yellow][9][/bold yellow] [bold cyan]System Doctor[/bold cyan]           — Environment diagnostics, dependencies, and database health\n\n"
            "  [bold green][D][/bold green] [bold white]Guided Sample Demo[/bold white]      — Walk through a simulated incident step-by-step\n"
            "  [bold magenta][G][/bold magenta] [bold white]Beginner's Guide[/bold white]        — 5 Golden Rules, forensic workflow & CLI cheatsheet\n"
            "  [bold red][Q][/bold red] [dim]Exit to Shell[/dim]"
        )

        console.print(
            Panel(
                menu_text,
                border_style="bright_blue",
                title="[bold red]LORDRON FORENSICS INTERACTIVE LAB[/bold red]",
                subtitle="[dim green]Choose an option to begin[/dim green]",
                expand=True,
            )
        )
        render_dashboard_footer()

        try:
            choice = Prompt.ask(
                Text("Enter selection [1-9, D, G, /help, /exit]"),
                default="D",
            ).strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Exiting LORDRON Forensics.[/dim]")
            break

        choice_lower = choice.lower()
        if choice_lower in ["q", "quit", "exit", "/exit", "/quit"]:
            console.print("[dim]Exiting LORDRON Forensics. Stay vigilant.[/dim]")
            break
        elif choice_lower in ["/help", "help", "/h", "-h", "--help"]:
            render_interactive_help()
            _pause()
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
            _pause()
        elif choice_lower in ["g", "guide", "cheat"]:
            display_forensic_guide()
            _pause()
        else:
            print_warning(f"Invalid selection '{choice}'. Please select 1-9, D, G, /help, or /exit.")
            _pause()
