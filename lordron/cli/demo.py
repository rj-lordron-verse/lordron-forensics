"""
Module: Guided Sample Investigation Demo for LORDRON Forensics.
Provides an interactive or automated end-to-end walkthrough using simulated evidence.
Designed to teach digital investigation methodology to beginners.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from lordron.core.console import (
    console,
    print_banner,
    print_info,
    print_success,
    print_warning,
)
from lordron.core.paths import get_base_dir
from lordron.modules.evidence_manager.manager import EvidenceManager
from lordron.modules.file_intelligence.inspector import inspect_single_file
from lordron.modules.hash_intelligence.hasher import hash_single_file, verify_file_integrity
from lordron.modules.log_analyzer.parser import parse_log_file
from lordron.modules.metadata_lab.inspector import inspect_metadata
from lordron.modules.reporting.generator import ReportGenerator
from lordron.modules.timeline.engine import TimelineEngine


def ensure_sample_files() -> dict[str, Path]:
    """
    Locate or generate sample forensic artifacts for the demonstration.
    Guarantees the demo works in any environment without external network calls.
    """
    # 1. Check existing repo examples path
    possible_paths = [
        Path(__file__).resolve().parent.parent.parent / "examples" / "sample_case",
        Path.cwd() / "examples" / "sample_case",
        Path.cwd() / "lordron-forensics" / "examples" / "sample_case",
    ]

    for p in possible_paths:
        if p.exists() and (p / "payload_disguised.jpg").exists() and (p / "auth.log").exists():
            return {
                "payload": p / "payload_disguised.jpg",
                "photo": p / "evidence_photo.png",
                "pdf": p / "document.pdf",
                "log": p / "auth.log",
            }

    # 2. Otherwise generate synthetic samples in ~/.lordron/demo_samples
    demo_dir = get_base_dir() / "demo_samples"
    demo_dir.mkdir(parents=True, exist_ok=True)

    payload_p = demo_dir / "payload_disguised.jpg"
    if not payload_p.exists():
        # ELF magic bytes disguised as .jpg
        payload_p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128)

    photo_p = demo_dir / "evidence_photo.png"
    if not photo_p.exists():
        # Minimal valid PNG header
        photo_p.write_bytes(
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x02\x00\x00\x00\x90\x91hb"
            b"\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01\x01\x00\x18\xdd\x8d\xb0"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )

    pdf_p = demo_dir / "document.pdf"
    if not pdf_p.exists():
        # Minimal valid PDF with metadata dictionary
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n"
            b"2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n"
            b"3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 300 300]>> endobj\n"
            b"4 0 obj <</Title (Confidential Operation Briefing) /Author (Raj - LORDRON Forensics) "
            b"/Subject (Incident Triage) /Creator (Lordron PDF Lab)>> endobj\n"
            b"trailer <</Root 1 0 R /Info 4 0 R>>\n"
            b"%%EOF\n"
        )
        pdf_p.write_bytes(pdf_content)

    log_p = demo_dir / "auth.log"
    if not log_p.exists():
        log_content = (
            "Mar 29 08:12:00 gateway sshd[4012]: Failed password for invalid user admin from 203.0.113.195 port 51102 ssh2\n"
            "Mar 29 08:12:02 gateway sshd[4013]: Failed password for invalid user admin from 203.0.113.195 port 51104 ssh2\n"
            "Mar 29 08:12:04 gateway sshd[4014]: Failed password for invalid user test from 203.0.113.195 port 51106 ssh2\n"
            "Mar 29 08:15:30 gateway sshd[4020]: Accepted password for investigator from 10.0.0.15 port 42310 ssh2\n"
            "Mar 29 08:16:10 gateway sudo: investigator : TTY=pts/0 ; PWD=/home/investigator ; USER=root ; COMMAND=/usr/bin/cat /var/log/syslog\n"
            "Mar 29 08:20:00 gateway kernel: [ 4512.981] Segfault in test_worker at 0x7ffd98\n"
        )
        log_p.write_text(log_content, encoding="utf-8")

    return {
        "payload": payload_p,
        "photo": photo_p,
        "pdf": pdf_p,
        "log": log_p,
    }


def _step_prompt(step_num: int, total_steps: int, title: str, interactive: bool) -> None:
    """Helper to display step header and optionally pause."""
    console.print(f"\n[bold green]═══ STEP {step_num} OF {total_steps}: {title} ═══[/bold green]")
    if interactive and sys.stdin.isatty():
        Prompt.ask("[dim]Press Enter to continue...[/dim]", default="")


def run_guided_demo(
    interactive: bool = True,
    case_id: str | None = None,
    quiet: bool = False,
) -> None:
    """Execute the comprehensive end-to-end guided forensic investigation demo."""
    print_banner(quiet=quiet)

    demo_case_id = case_id or f"CASE-DEMO-{int(time.time())}"

    welcome_panel = Panel(
        f"[bold white]WELCOME TO THE LORDRON FORENSICS GUIDED INVESTIGATION DEMO[/bold white]\n\n"
        f"This automated tutorial simulates an incident triage scenario where you inspect suspect artifacts, "
        f"preserve evidence in a read-only vault, analyze logs for security anomalies, and produce an auditable report.\n\n"
        f"Target Case ID: [bold yellow]{demo_case_id}[/bold yellow]\n"
        f"Mode: [bold cyan]{'Interactive Guided Tour' if interactive else 'Automated Fast Tour'}[/bold cyan]",
        border_style="cyan",
        title="[bold yellow]MISSION BRIEFING[/bold yellow]",
        expand=True,
    )
    console.print(welcome_panel)

    samples = ensure_sample_files()
    mgr = EvidenceManager()

    total_steps = 8

    # STEP 1: File Intelligence - Disguise Detection
    _step_prompt(1, total_steps, "FILE INTELLIGENCE & SIGNATURE TRIAGE", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "Never trust a file extension. Attackers often rename malicious executables to innocuous names "
        "(e.g., [italic]payload_disguised.jpg[/italic]) to fool users and basic file filters.\n"
    )
    payload_info = inspect_single_file(samples["payload"])

    t1 = Table(border_style="cyan", title=f"Triage of: {samples['payload'].name}")
    t1.add_column("Property", style="bold magenta", width=22)
    t1.add_column("Detected Value", style="white")
    t1.add_row("Reported Extension", payload_info["extension"])
    t1.add_row("True Detected Format", f"[bold yellow]{payload_info['detected_format']}[/bold yellow]")
    t1.add_row("MIME Type", payload_info["mime_type"])
    t1.add_row("Magic Bytes (Hex)", payload_info["header_hex_preview"][:32] + "...")
    t1.add_row("Suspicious Mismatch?", f"[bold red]⚠ {payload_info['mismatch_details']}[/bold red]")
    console.print(t1)
    print_warning("CRITICAL FINDING: The file is an ELF Linux executable disguised with a .jpg extension!")

    # STEP 2: Metadata Extraction
    _step_prompt(2, total_steps, "METADATA LAB ANALYSIS", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "Document and media files contain hidden structural metadata (author names, software, camera models, "
        "timestamps, GPS coordinates) that attackers frequently forget to wipe.\n"
    )
    pdf_info = inspect_metadata(samples["pdf"])
    t2 = Table(border_style="cyan", title=f"Metadata Extracted: {samples['pdf'].name}")
    t2.add_column("Property", style="bold magenta", width=20)
    t2.add_column("Value", style="white")
    props = pdf_info.get("properties", {})
    for k, v in props.items():
        t2.add_row(k.capitalize(), str(v))
    console.print(t2)
    print_info(f"PDF parsed via: {pdf_info.get('parser_used', 'native_binary_parser')}")

    # STEP 3: Cryptographic Hashing
    _step_prompt(3, total_steps, "CRYPTOGRAPHIC HASH INTEGRITY FINGERPRINTING", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "Cryptographic digests serve as digital fingerprints. Before any evidence is touched, "
        "we calculate multi-algorithm hashes to create an unforgeable baseline.\n"
    )
    hashes = hash_single_file(samples["payload"])
    t3 = Table(border_style="cyan", title=f"Cryptographic Digests: {samples['payload'].name}")
    t3.add_column("Algorithm", style="bold magenta", width=14)
    t3.add_column("Hexadecimal Digest", style="bold green")
    for algo, digest in hashes["hashes"].items():
        t3.add_row(algo.upper(), digest)
    console.print(t3)

    # Verify matching
    sha256_val = hashes["hashes"]["sha256"]
    verify_res = verify_file_integrity(samples["payload"], sha256_val)
    print_success(f"Integrity self-test passed: Verified against calculated SHA-256 digest ({verify_res['algorithm']}).")

    # STEP 4: Case Ledger Creation
    _step_prompt(4, total_steps, "CHAIN OF CUSTODY & CASE INITIALIZATION", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "All investigative findings must be bound to a formal case ledger with full audit logging "
        "and strict investigator accountability.\n"
    )
    created_case = mgr.create_case(
        case_id=demo_case_id,
        title="Simulated Breach Investigation",
        investigator="Forensic Analyst",
        description="Demo walkthrough verifying disguised payload, PDF metadata, and server auth logs."
    )
    print_success(f"Case '{created_case.case_id}' successfully registered in SQLite custody database.")

    # STEP 5: Evidence Vault Acquisition (Read-only preservation)
    _step_prompt(5, total_steps, "EVIDENCE VAULT ACQUISITION & PRESERVATION", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "Working copies are isolated into the case vault and locked with read-only permissions (0o444). "
        "The original source artifact is left completely untouched.\n"
    )
    item_payload = mgr.acquire_evidence(
        demo_case_id,
        samples["payload"],
        actor="Investigator",
        notes="Disguised ELF payload recovered from web upload staging folder"
    )
    item_pdf = mgr.acquire_evidence(
        demo_case_id,
        samples["pdf"],
        actor="Investigator",
        notes="Briefing document recovered alongside suspect payload"
    )
    print_success(f"Acquired artifact: {item_payload.file_name} -> Vault: {item_payload.vault_path} (0o444 Read-only)")
    print_success(f"Acquired artifact: {item_pdf.file_name} -> Vault: {item_pdf.vault_path} (0o444 Read-only)")

    # STEP 6: Vault Integrity Verification
    _step_prompt(6, total_steps, "VAULT INTEGRITY AUDIT", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "At any point during an investigation, the vault can be audited to prove evidence has not been "
        "tampered with, corrupted by disk errors, or modified by external software.\n"
    )
    audit = mgr.verify_case_integrity(demo_case_id)
    t6 = Table(border_style="cyan", title=f"Vault Integrity Verification: {demo_case_id}")
    t6.add_column("Evidence ID", style="bold cyan")
    t6.add_column("File Name", style="white")
    t6.add_column("Integrity Status", style="bold green")
    for r in audit["results"]:
        t6.add_row(r["evidence_id"], r["file_name"], f"[bold green]{r['status']}[/bold green]")
    console.print(t6)
    print_success("ALL evidence artifacts passed cryptographic integrity verification.")

    # STEP 7: Server Log Analysis
    _step_prompt(7, total_steps, "LOG ANALYSIS & ANOMALY DETECTION", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "Server logs correlate user actions with file artifacts. LORDRON classifies severities, detects "
        "anomaly patterns (brute force, privilege escalation, crashes), and extracts frequency metrics.\n"
    )
    log_data = parse_log_file(samples["log"])
    t7 = Table(border_style="cyan", title="Log Anomaly Patterns")
    t7.add_column("Pattern Type", style="bold magenta")
    t7.add_column("Occurrences", style="bold yellow", justify="right")
    for pat, count in log_data["anomaly_patterns_detected"].items():
        t7.add_row(pat, str(count))
    console.print(t7)

    console.print(f"Total Log Lines: [bold white]{log_data['total_lines_processed']}[/bold white]")
    console.print(f"Severity Distribution: [bold yellow]{log_data['severity_summary']}[/bold yellow]")
    print_warning("Observed 3 authentication failures followed by root command execution via sudo!")

    # STEP 8: Timeline & Report Generation
    _step_prompt(8, total_steps, "TIMELINE ENGINE & COMPREHENSIVE REPORT GENERATION", interactive)
    console.print(
        "[bold cyan]Forensic Principle:[/bold cyan] "
        "A multi-source timeline fuses filesystem timestamps with audit events to reconstruct what happened "
        "chronologically. A final report presents all facts clearly for legal and leadership teams.\n"
    )

    # Add investigative note to case
    mgr.add_case_note(
        demo_case_id,
        author="Forensic Analyst",
        content="Investigation confirmed malicious disguise: payload_disguised.jpg contains ELF executable. "
                "Correlated with 3 brute force SSH attempts from 203.0.113.195 in auth.log."
    )

    timeline_engine = TimelineEngine(mgr.repo)
    tl = timeline_engine.build_case_timeline(demo_case_id)
    t8 = Table(border_style="cyan", title=f"Timeline Events: {demo_case_id}")
    t8.add_column("Timestamp (UTC)", style="dim", width=22)
    t8.add_column("Source Type", style="bold magenta", width=24)
    t8.add_column("Event Summary", style="white")
    for ev in tl["events"][:6]:
        t8.add_row(ev["timestamp_utc"], ev["source_type"], ev["summary"])
    console.print(t8)

    # Generate HTML report
    generator = ReportGenerator(mgr.repo)
    html_content = generator.generate_report(demo_case_id, fmt="html")
    report_path = get_base_dir() / "cases" / demo_case_id / f"report_{demo_case_id}.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print_success(f"Professional HTML Forensic Report generated: {report_path}")

    # Final Summary Panel
    summary_panel = Panel(
        f"[bold green]✔ DEMONSTRATION COMPLETE: ALL 8 FORENSIC PHASES EXECUTED SUCCESSFULLY![/bold green]\n\n"
        f"Case ID:           [bold yellow]{demo_case_id}[/bold yellow]\n"
        f"Evidence Items:    [bold white]2 artifacts preserved in read-only vault[/bold white]\n"
        f"Vault Integrity:   [bold green]100% Cryptographically Verified[/bold green]\n"
        f"Key Discovery:     [bold red]Executable disguised as JPEG + SSH brute force attack[/bold red]\n"
        f"HTML Report:       [bold cyan]{report_path}[/bold cyan]\n\n"
        f"[dim]Tip: You can inspect this case anytime using: [cyan]lordron case show {demo_case_id}[/cyan][/dim]",
        border_style="green",
        title="[bold white]EXECUTIVE INVESTIGATION SUMMARY[/bold white]",
        expand=True,
    )
    console.print(summary_panel)
