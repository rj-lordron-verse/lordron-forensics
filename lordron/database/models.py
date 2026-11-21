"""
Data models representing forensic cases, evidence artifacts, and audit trails.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Case:
    case_id: str
    title: str
    investigator: str
    description: str
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: str = "OPEN"


@dataclass
class EvidenceItem:
    evidence_id: str
    case_id: str
    original_path: str
    vault_path: str
    file_name: str
    file_size_bytes: int
    detected_format: str
    sha256_at_acquisition: str
    sha512_at_acquisition: str
    md5_legacy: str
    acquisition_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_verified_utc: Optional[str] = None
    integrity_status: str = "ACQUIRED"
    notes: Optional[str] = None


@dataclass
class AuditLog:
    id: Optional[int]
    case_id: str
    action: str
    actor: str
    details: str
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class CaseNote:
    id: Optional[int]
    case_id: str
    author: str
    content: str
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
