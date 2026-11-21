"""
HTML report generator for LORDRON Forensics.
Generates responsive, self-contained forensic reports with LORDRON branding.
"""

from __future__ import annotations
import html
from typing import Dict, Any


def generate_html_report(report_data: Dict[str, Any]) -> str:
    """Generate a clean, standalone, responsive HTML investigation report."""
    case = report_data.get("case", {})
    evidence_list = report_data.get("evidence", [])
    timeline_events = report_data.get("timeline", {}).get("events", [])
    notes = report_data.get("notes", [])
    integrity = report_data.get("integrity_summary", {})

    all_passed = integrity.get("overall_integrity_passed", True)
    badge_color = "#10b981" if all_passed else "#ef4444"
    badge_text = "INTEGRITY VERIFIED" if all_passed else "INTEGRITY ALERT / COMPROMISED"

    # Escape dynamic strings for safety
    case_id = html.escape(str(case.get("case_id", "")))
    title = html.escape(str(case.get("title", "")))
    investigator = html.escape(str(case.get("investigator", "Raj")))
    gen_time = html.escape(str(report_data.get("generated_at_utc", "")))

    evidence_rows = []
    for item in evidence_list:
        ev_id = html.escape(str(item.get("evidence_id", "")))
        fn = html.escape(str(item.get("file_name", "")))
        sz = f"{item.get('file_size_bytes', 0):,} bytes"
        fmt = html.escape(str(item.get("detected_format", "")))
        h256 = html.escape(str(item.get("sha256_at_acquisition", "")))
        st = html.escape(str(item.get("integrity_status", "")))
        st_color = "#10b981" if "VERIFIED" in st else "#f59e0b"

        evidence_rows.append(f"""
        <tr>
            <td style="font-weight: 600; font-family: monospace;">{ev_id}</td>
            <td><strong>{fn}</strong></td>
            <td>{fmt}</td>
            <td>{sz}</td>
            <td><code style="word-break: break-all; font-size: 0.85em;">{h256}</code></td>
            <td><span style="color: {st_color}; font-weight: 600;">{st}</span></td>
        </tr>
        """)

    timeline_rows = []
    for ev in timeline_events:
        ts = html.escape(str(ev.get("timestamp_utc", "")))
        src = html.escape(str(ev.get("source_type", "")))
        summary = html.escape(str(ev.get("summary", "")))
        warn = ev.get("reliability_warning")
        warn_html = f'<div style="color: #ef4444; font-size: 0.8em; margin-top: 4px;">⚠ {html.escape(warn)}</div>' if warn else ""

        timeline_rows.append(f"""
        <tr>
            <td style="white-space: nowrap; font-family: monospace;">{ts}</td>
            <td><span class="badge badge-source">{src}</span></td>
            <td>{summary}{warn_html}</td>
        </tr>
        """)

    notes_html = []
    for n in notes:
        n_author = html.escape(str(n.get("author", "")))
        n_time = html.escape(str(n.get("timestamp_utc", "")))
        n_content = html.escape(str(n.get("content", "")))
        notes_html.append(f"""
        <div class="note-card">
            <div style="font-size: 0.85em; color: #94a3b8; margin-bottom: 6px;">
                <strong>{n_author}</strong> on {n_time}
            </div>
            <div style="white-space: pre-wrap;">{n_content}</div>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LORDRON Forensics Report - Case {case_id}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .brand-title {{
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: 1px;
            color: var(--accent-cyan);
        }}
        .tagline {{
            color: #fbbf24;
            font-style: italic;
            font-size: 0.95rem;
            margin-top: 4px;
        }}
        .meta-pill {{
            background-color: rgba(6, 182, 212, 0.1);
            border: 1px solid var(--accent-cyan);
            border-radius: 8px;
            padding: 10px 16px;
            font-size: 0.85rem;
            text-align: right;
        }}
        .card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 25px;
        }}
        .card h2 {{
            font-size: 1.25rem;
            color: var(--accent-cyan);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .badge {{
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 0.8rem;
            font-weight: 700;
            display: inline-block;
        }}
        .badge-source {{
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border: 1px solid #3b82f6;
            font-family: monospace;
            font-size: 0.75rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            font-size: 0.9rem;
        }}
        th, td {{
            text-align: left;
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(15, 23, 42, 0.6);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.5px;
        }}
        tr:hover {{
            background-color: rgba(255, 255, 255, 0.02);
        }}
        .grid-2 {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
            margin-bottom: 10px;
        }}
        .stat-box {{
            background-color: rgba(15, 23, 42, 0.4);
            border: 1px solid var(--border-color);
            padding: 14px;
            border-radius: 8px;
        }}
        .stat-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
        }}
        .stat-val {{
            font-size: 1.1rem;
            font-weight: 700;
            margin-top: 4px;
        }}
        .note-card {{
            background-color: rgba(15, 23, 42, 0.5);
            border-left: 4px solid var(--accent-cyan);
            padding: 14px;
            border-radius: 4px;
            margin-bottom: 12px;
        }}
        .disclaimer-box {{
            background-color: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 8px;
            padding: 16px;
            font-size: 0.85rem;
            color: #fca5a5;
            margin-top: 20px;
        }}
        footer {{
            text-align: center;
            font-size: 0.8rem;
            color: var(--text-secondary);
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <div class="brand-title">LORDRON FORENSICS</div>
                <div class="tagline">"Every File Has a Story. Find It."</div>
                <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 6px;">
                    Digital Investigation Toolkit • Version 1.0.0
                </div>
            </div>
            <div class="meta-pill">
                <div><strong>Case ID:</strong> {case_id}</div>
                <div><strong>Investigator:</strong> {investigator}</div>
                <div><strong>Generated:</strong> {gen_time}</div>
            </div>
        </header>

        <section class="card">
            <h2>
                <span>Case Overview</span>
                <span class="badge" style="background-color: {badge_color}22; color: {badge_color}; border: 1px solid {badge_color};">
                    {badge_text}
                </span>
            </h2>
            <div class="grid-2">
                <div class="stat-box">
                    <div class="stat-label">Title</div>
                    <div class="stat-val">{title}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Investigation Status</div>
                    <div class="stat-val">{case.get('status', 'OPEN')}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Evidence Items</div>
                    <div class="stat-val">{len(evidence_list)}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Case Inception (UTC)</div>
                    <div class="stat-val" style="font-size: 0.95rem; font-family: monospace;">{case.get('created_at_utc', '')}</div>
                </div>
            </div>
        </section>

        <section class="card">
            <h2>Evidence Inventory & Integrity Ledger</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Evidence ID</th>
                            <th>Artifact Name</th>
                            <th>Format</th>
                            <th>Size</th>
                            <th>Acquisition SHA256</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(evidence_rows) if evidence_rows else '<tr><td colspan="6" style="text-align:center;">No evidence items registered.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="card">
            <h2>Multi-Source Chronological Timeline</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp (UTC)</th>
                            <th>Source Classification</th>
                            <th>Event Summary</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(timeline_rows) if timeline_rows else '<tr><td colspan="3" style="text-align:center;">No timeline events recorded.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </section>

        <section class="card">
            <h2>Investigator Notes</h2>
            <div>
                {''.join(notes_html) if notes_html else '<p style="color: var(--text-secondary);">No notes recorded for this case.</p>'}
            </div>
        </section>

        <div class="disclaimer-box">
            <strong>CRITICAL FORENSIC LIMITATIONS & LEGAL NOTICE:</strong><br>
            1. <strong>Separation of Fact vs. Interpretation:</strong> Cryptographic digests, raw byte signatures, and file dimensions represent observed empirical facts. Anomaly tags, severity classes, and log patterns represent investigative heuristics and do not constitute independent proof of malicious intent.<br>
            2. <strong>Filesystem Timestamps:</strong> Timestamps extracted from filesystems (mtime/ctime/atime) are susceptible to timestomping and clock drift. They must be corroborated.<br>
            3. <strong>Tamper Notice:</strong> SQLite audit logs are maintained for organizational traceability and chain of custody; they are not independently tamper-proof against deliberate host database modifications without external WORM or hardware-backed signing.
        </div>

        <footer>
            LORDRON Forensics Toolkit • Created by Raj | Brand: LORDRON • Offline-First Architecture
        </footer>
    </div>
</body>
</html>"""
