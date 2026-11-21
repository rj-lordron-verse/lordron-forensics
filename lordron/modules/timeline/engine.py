"""
Module 06: Timeline Engine
Chronological multi-source event fusion: fuses filesystem timestamps, evidence acquisition,
audit records, and investigator notes while keeping sources clearly distinct.
"""

from __future__ import annotations
import platform
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from lordron.database.repository import ForensicsRepository
from lordron.core.exceptions import CaseNotFoundError


@dataclass
class TimelineEvent:
    timestamp_utc: str
    source_type: str  # e.g., 'EVIDENCE_ACQUISITION', 'FILESYSTEM_MTIME', 'AUDIT_RECORD', 'INVESTIGATOR_NOTE'
    entity_id: str
    summary: str
    reliability_warning: Optional[str] = None


class TimelineEngine:
    """Builds unified, source-distinguished chronological timelines for a case."""

    def __init__(self, repo: Optional[ForensicsRepository] = None):
        self.repo = repo or ForensicsRepository()

    def build_case_timeline(self, case_id: str) -> Dict[str, Any]:
        """Aggregate all timeline artifacts for a case in chronological order."""
        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' does not exist.")

        evidence_items = self.repo.list_evidence(case_id)
        audit_logs = self.repo.list_audit_logs(case_id)
        notes = self.repo.list_notes(case_id)

        events: List[TimelineEvent] = []

        # 1. Case creation event
        events.append(
            TimelineEvent(
                timestamp_utc=case.created_at_utc,
                source_type="CASE_CREATION",
                entity_id=case.case_id,
                summary=f"Case '{case.title}' created by {case.investigator}",
                reliability_warning=None,
            )
        )

        # 2. Evidence events (acquisition & filesystem timestamps)
        for item in evidence_items:
            # Acquisition event
            events.append(
                TimelineEvent(
                    timestamp_utc=item.acquisition_utc,
                    source_type="EVIDENCE_ACQUISITION_UTC",
                    entity_id=item.evidence_id,
                    summary=f"Evidence acquired: '{item.file_name}' (SHA256: {item.sha256_at_acquisition[:16]}...)",
                    reliability_warning=None,
                )
            )

            # Filesystem timestamps from vault / original file if accessible
            vault_p = Path(item.vault_path)
            if vault_p.exists():
                stat = vault_p.stat()
                mtime_utc = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                ctime_utc = datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat()

                events.append(
                    TimelineEvent(
                        timestamp_utc=mtime_utc,
                        source_type="FILESYSTEM_MTIME",
                        entity_id=item.evidence_id,
                        summary=f"Filesystem Last Modified time for '{item.file_name}'",
                        reliability_warning="CAUTION: Filesystem timestamps are easily altered/timestomped and not proof of event time.",
                    )
                )

                if hasattr(stat, "st_birthtime"):
                    birth_utc = datetime.fromtimestamp(stat.st_birthtime, tz=timezone.utc).isoformat()
                    events.append(
                        TimelineEvent(
                            timestamp_utc=birth_utc,
                            source_type="FILESYSTEM_BIRTHTIME",
                            entity_id=item.evidence_id,
                            summary=f"Filesystem Creation (Birth) time for '{item.file_name}' (macOS/BSD)",
                            reliability_warning="CAUTION: Filesystem timestamps are easily altered/timestomped and susceptible to clock skew.",
                        )
                    )

                is_win = (platform.system() == "Windows")
                ctime_label = (
                    f"Filesystem Creation time for '{item.file_name}' (Windows ctime)"
                    if is_win
                    else f"Filesystem Metadata Changed time for '{item.file_name}' (POSIX ctime)"
                )
                events.append(
                    TimelineEvent(
                        timestamp_utc=ctime_utc,
                        source_type="FILESYSTEM_CTIME",
                        entity_id=item.evidence_id,
                        summary=ctime_label,
                        reliability_warning="CAUTION: Filesystem timestamps are easily altered/timestomped and susceptible to clock skew.",
                    )
                )

        # 3. Audit logs
        for log in audit_logs:
            if log.action not in ["CASE_CREATED", "EVIDENCE_ACQUIRED"]:
                events.append(
                    TimelineEvent(
                        timestamp_utc=log.timestamp_utc,
                        source_type="AUDIT_RECORD",
                        entity_id=f"AUDIT-{log.id or 0}",
                        summary=f"[{log.actor}] {log.action}: {log.details}",
                        reliability_warning=None,
                    )
                )

        # 4. Investigator notes
        for note in notes:
            events.append(
                TimelineEvent(
                    timestamp_utc=note.timestamp_utc,
                    source_type="INVESTIGATOR_NOTE",
                    entity_id=f"NOTE-{note.id or 0}",
                    summary=f"Investigator Note ({note.author}): {note.content[:100]}",
                    reliability_warning=None,
                )
            )

        # Chronological sort
        def _sort_key(ev: TimelineEvent):
            try:
                # Handle ISO 8601 strings
                return ev.timestamp_utc
            except Exception:
                return "1970-01-01T00:00:00Z"

        events.sort(key=_sort_key)

        return {
            "case_id": case_id,
            "case_title": case.title,
            "total_events": len(events),
            "events": [
                {
                    "timestamp_utc": ev.timestamp_utc,
                    "source_type": ev.source_type,
                    "entity_id": ev.entity_id,
                    "summary": ev.summary,
                    "reliability_warning": ev.reliability_warning,
                }
                for ev in events
            ],
            "forensic_disclaimer": (
                "CRITICAL: Filesystem timestamps (mtime/ctime/atime) should never be treated as independent proof of "
                "when an event occurred. They are subject to timestomping, application modifications, and filesystem clock drift."
            )
        }
