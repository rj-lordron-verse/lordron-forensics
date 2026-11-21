"""
CSV report generator for LORDRON Forensics.
Produces standard tabular evidence inventory and timeline exports.
"""

from __future__ import annotations
import csv
import io
from typing import Dict, Any


def generate_csv_report(report_data: Dict[str, Any]) -> str:
    """Export case evidence inventory and chronological timeline as CSV sections."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header / Meta
    case = report_data.get("case", {})
    writer.writerow(["# LORDRON FORENSICS INVESTIGATION EXPORT"])
    writer.writerow(["Case ID", case.get("case_id")])
    writer.writerow(["Case Title", case.get("title")])
    writer.writerow(["Investigator", case.get("investigator")])
    writer.writerow(["Generated At UTC", report_data.get("generated_at_utc")])
    writer.writerow([])

    # Evidence Inventory Table
    writer.writerow(["[EVIDENCE INVENTORY]"])
    writer.writerow([
        "Evidence ID", "File Name", "Size Bytes", "Format",
        "Acquisition SHA256", "Acquisition UTC", "Integrity Status"
    ])
    for item in report_data.get("evidence", []):
        writer.writerow([
            item.get("evidence_id"),
            item.get("file_name"),
            item.get("file_size_bytes"),
            item.get("detected_format"),
            item.get("sha256_at_acquisition"),
            item.get("acquisition_utc"),
            item.get("integrity_status"),
        ])
    writer.writerow([])

    # Timeline Table
    writer.writerow(["[CASE TIMELINE]"])
    writer.writerow(["Timestamp UTC", "Source Type", "Entity ID", "Summary", "Reliability Warning"])
    for ev in report_data.get("timeline", {}).get("events", []):
        writer.writerow([
            ev.get("timestamp_utc"),
            ev.get("source_type"),
            ev.get("entity_id"),
            ev.get("summary"),
            ev.get("reliability_warning") or "NONE",
        ])

    return output.getvalue()
