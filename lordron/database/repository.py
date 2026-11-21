"""
SQLite database repository and transaction management for LORDRON Forensics.
"""

from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional, List
from lordron.core.paths import get_database_path
from lordron.core.exceptions import CaseNotFoundError, CaseAlreadyExistsError
from lordron.database.models import Case, EvidenceItem, AuditLog, CaseNote

SCHEMA_PATH = Path(__file__).parent / "migrations" / "schema.sql"


class ForensicsRepository:
    """Manages SQLite storage for investigation cases, evidence custody, and audits."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or get_database_path()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        """Apply schema if database is newly initialized."""
        with self._get_connection() as conn:
            with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            conn.executescript(schema_sql)

    def create_case(self, case: Case) -> Case:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT case_id FROM cases WHERE case_id = ?", (case.case_id,))
            if cursor.fetchone():
                raise CaseAlreadyExistsError(f"Case with ID '{case.case_id}' already exists.")

            cursor.execute(
                """
                INSERT INTO cases (case_id, title, investigator, description, created_at_utc, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case.case_id,
                    case.title,
                    case.investigator,
                    case.description,
                    case.created_at_utc,
                    case.status,
                ),
            )
            self.add_audit_log(
                AuditLog(
                    id=None,
                    case_id=case.case_id,
                    action="CASE_CREATED",
                    actor=case.investigator,
                    details=f"Case '{case.title}' created.",
                    timestamp_utc=case.created_at_utc,
                ),
                connection=conn,
            )
        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return Case(
                case_id=row["case_id"],
                title=row["title"],
                investigator=row["investigator"],
                description=row["description"],
                created_at_utc=row["created_at_utc"],
                status=row["status"],
            )

    def list_cases(self) -> List[Case]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases ORDER BY created_at_utc DESC")
            rows = cursor.fetchall()
            return [
                Case(
                    case_id=row["case_id"],
                    title=row["title"],
                    investigator=row["investigator"],
                    description=row["description"],
                    created_at_utc=row["created_at_utc"],
                    status=row["status"],
                )
                for row in rows
            ]

    def add_evidence(self, item: EvidenceItem, actor: str = "Investigator") -> EvidenceItem:
        with self._get_connection() as conn:
            # Check case exists
            cursor = conn.cursor()
            cursor.execute("SELECT case_id FROM cases WHERE case_id = ?", (item.case_id,))
            if not cursor.fetchone():
                raise CaseNotFoundError(f"Case '{item.case_id}' not found.")

            cursor.execute(
                """
                INSERT INTO evidence (
                    evidence_id, case_id, original_path, vault_path, file_name,
                    file_size_bytes, detected_format, sha256_at_acquisition,
                    sha512_at_acquisition, md5_legacy, acquisition_utc,
                    last_verified_utc, integrity_status, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.evidence_id,
                    item.case_id,
                    item.original_path,
                    item.vault_path,
                    item.file_name,
                    item.file_size_bytes,
                    item.detected_format,
                    item.sha256_at_acquisition,
                    item.sha512_at_acquisition,
                    item.md5_legacy,
                    item.acquisition_utc,
                    item.last_verified_utc,
                    item.integrity_status,
                    item.notes,
                ),
            )
            self.add_audit_log(
                AuditLog(
                    id=None,
                    case_id=item.case_id,
                    action="EVIDENCE_ACQUIRED",
                    actor=actor,
                    details=f"Acquired '{item.file_name}' (ID: {item.evidence_id}, SHA256: {item.sha256_at_acquisition})",
                    timestamp_utc=item.acquisition_utc,
                ),
                connection=conn,
            )
        return item

    def get_evidence(self, evidence_id: str) -> Optional[EvidenceItem]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return EvidenceItem(
                evidence_id=row["evidence_id"],
                case_id=row["case_id"],
                original_path=row["original_path"],
                vault_path=row["vault_path"],
                file_name=row["file_name"],
                file_size_bytes=row["file_size_bytes"],
                detected_format=row["detected_format"],
                sha256_at_acquisition=row["sha256_at_acquisition"],
                sha512_at_acquisition=row["sha512_at_acquisition"],
                md5_legacy=row["md5_legacy"],
                acquisition_utc=row["acquisition_utc"],
                last_verified_utc=row["last_verified_utc"],
                integrity_status=row["integrity_status"],
                notes=row["notes"],
            )

    def list_evidence(self, case_id: str) -> List[EvidenceItem]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM evidence WHERE case_id = ? ORDER BY acquisition_utc ASC",
                (case_id,),
            )
            rows = cursor.fetchall()
            return [
                EvidenceItem(
                    evidence_id=row["evidence_id"],
                    case_id=row["case_id"],
                    original_path=row["original_path"],
                    vault_path=row["vault_path"],
                    file_name=row["file_name"],
                    file_size_bytes=row["file_size_bytes"],
                    detected_format=row["detected_format"],
                    sha256_at_acquisition=row["sha256_at_acquisition"],
                    sha512_at_acquisition=row["sha512_at_acquisition"],
                    md5_legacy=row["md5_legacy"],
                    acquisition_utc=row["acquisition_utc"],
                    last_verified_utc=row["last_verified_utc"],
                    integrity_status=row["integrity_status"],
                    notes=row["notes"],
                )
                for row in rows
            ]

    def update_evidence_verification(
        self, evidence_id: str, status: str, verified_utc: str
    ) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE evidence
                SET integrity_status = ?, last_verified_utc = ?
                WHERE evidence_id = ?
                """,
                (status, verified_utc, evidence_id),
            )

    def add_audit_log(
        self, log: AuditLog, connection: Optional[sqlite3.Connection] = None
    ) -> AuditLog:
        def _insert(conn: sqlite3.Connection):
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_logs (case_id, action, actor, details, timestamp_utc)
                VALUES (?, ?, ?, ?, ?)
                """,
                (log.case_id, log.action, log.actor, log.details, log.timestamp_utc),
            )
            log.id = cursor.lastrowid

        if connection:
            _insert(connection)
        else:
            with self._get_connection() as conn:
                _insert(conn)
        return log

    def list_audit_logs(self, case_id: str) -> List[AuditLog]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM audit_logs WHERE case_id = ? ORDER BY timestamp_utc ASC",
                (case_id,),
            )
            rows = cursor.fetchall()
            return [
                AuditLog(
                    id=row["id"],
                    case_id=row["case_id"],
                    action=row["action"],
                    actor=row["actor"],
                    details=row["details"],
                    timestamp_utc=row["timestamp_utc"],
                )
                for row in rows
            ]

    def add_note(self, note: CaseNote) -> CaseNote:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO case_notes (case_id, author, content, timestamp_utc)
                VALUES (?, ?, ?, ?)
                """,
                (note.case_id, note.author, note.content, note.timestamp_utc),
            )
            note.id = cursor.lastrowid
            self.add_audit_log(
                AuditLog(
                    id=None,
                    case_id=note.case_id,
                    action="NOTE_ADDED",
                    actor=note.author,
                    details=f"Investigator note recorded (id: {note.id})",
                    timestamp_utc=note.timestamp_utc,
                ),
                connection=conn,
            )
        return note

    def list_notes(self, case_id: str) -> List[CaseNote]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM case_notes WHERE case_id = ? ORDER BY timestamp_utc ASC",
                (case_id,),
            )
            rows = cursor.fetchall()
            return [
                CaseNote(
                    id=row["id"],
                    case_id=row["case_id"],
                    author=row["author"],
                    content=row["content"],
                    timestamp_utc=row["timestamp_utc"],
                )
                for row in rows
            ]
