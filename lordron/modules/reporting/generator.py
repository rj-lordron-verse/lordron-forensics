"""
Module 08: Report Generator
Compiles unified evidence reports in HTML, JSON, or CSV format.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from lordron.database.repository import ForensicsRepository
from lordron.modules.evidence_manager.manager import EvidenceManager
from lordron.modules.timeline.engine import TimelineEngine
from lordron.modules.reporting.html_reporter import generate_html_report
from lordron.modules.reporting.json_reporter import generate_json_report
from lordron.modules.reporting.csv_reporter import generate_csv_report
from lordron.core.exceptions import CaseNotFoundError


class ReportGenerator:
    """Orchestrates comprehensive report creation across formats."""

    def __init__(self, repo: Optional[ForensicsRepository] = None):
        self.repo = repo or ForensicsRepository()
        self.evidence_mgr = EvidenceManager(self.repo)
        self.timeline_engine = TimelineEngine(self.repo)

    def compile_case_data(self, case_id: str) -> Dict[str, Any]:
        """Collect all case records, evidence items, integrity checks, and timeline."""
        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' does not exist.")

        evidence_items = self.repo.list_evidence(case_id)
        notes = self.repo.list_notes(case_id)
        audit_logs = self.repo.list_audit_logs(case_id)
        integrity_summary = self.evidence_mgr.verify_case_integrity(case_id)
        timeline = self.timeline_engine.build_case_timeline(case_id)

        return {
            "tool": {
                "name": "LORDRON FORENSICS",
                "version": "1.0.0",
                "brand": "LORDRON",
                "author": "Raj",
                "tagline": "Every File Has a Story. Find It.",
            },
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "case": {
                "case_id": case.case_id,
                "title": case.title,
                "investigator": case.investigator,
                "description": case.description,
                "created_at_utc": case.created_at_utc,
                "status": case.status,
            },
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "file_name": item.file_name,
                    "original_path": item.original_path,
                    "file_size_bytes": item.file_size_bytes,
                    "detected_format": item.detected_format,
                    "sha256_at_acquisition": item.sha256_at_acquisition,
                    "sha512_at_acquisition": item.sha512_at_acquisition,
                    "md5_legacy": item.md5_legacy,
                    "acquisition_utc": item.acquisition_utc,
                    "last_verified_utc": item.last_verified_utc,
                    "integrity_status": item.integrity_status,
                    "notes": item.notes,
                }
                for item in evidence_items
            ],
            "notes": [
                {
                    "author": n.author,
                    "content": n.content,
                    "timestamp_utc": n.timestamp_utc,
                }
                for n in notes
            ],
            "audit_logs": [
                {
                    "action": a.action,
                    "actor": a.actor,
                    "details": a.details,
                    "timestamp_utc": a.timestamp_utc,
                }
                for a in audit_logs
            ],
            "integrity_summary": integrity_summary,
            "timeline": timeline,
        }

    def generate_report(self, case_id: str, fmt: str = "html") -> str:
        """Compile and format the case report in 'html', 'json', or 'csv'."""
        data = self.compile_case_data(case_id)
        fmt_clean = fmt.lower().strip()

        if fmt_clean == "html":
            return generate_html_report(data)
        elif fmt_clean == "json":
            return generate_json_report(data)
        elif fmt_clean == "csv":
            return generate_csv_report(data)
        else:
            raise ValueError(f"Unsupported report format '{fmt}'. Choose 'html', 'json', or 'csv'.")
