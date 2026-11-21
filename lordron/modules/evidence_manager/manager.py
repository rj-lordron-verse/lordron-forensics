"""
Module 04: Evidence Manager
Handles case lifecycle, secure evidence acquisition, read-only preservation,
audit logging, and cryptographic integrity verification.
"""

from __future__ import annotations
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from lordron.core.paths import get_cases_dir, validate_file_path
from lordron.core.file_detection import inspect_file
from lordron.core.hashing import calculate_hashes
from lordron.core.exceptions import CaseNotFoundError
from lordron.database.models import Case, EvidenceItem, AuditLog, CaseNote
from lordron.database.repository import ForensicsRepository


class EvidenceManager:
    """Provides evidence acquisition, chain of custody, and case management."""

    def __init__(self, repo: Optional[ForensicsRepository] = None):
        self.repo = repo or ForensicsRepository()

    def create_case(
        self,
        case_id: str,
        title: Optional[str] = None,
        investigator: str = "Raj",
        description: str = "Digital investigation case"
    ) -> Case:
        """Create a new forensic case and initialize its local evidence vault."""
        clean_id = case_id.strip()
        case_title = title or f"Case {clean_id}"

        # Initialize case folder
        case_vault = get_cases_dir() / clean_id / "evidence"
        case_vault.mkdir(parents=True, exist_ok=True)

        case = Case(
            case_id=clean_id,
            title=case_title,
            investigator=investigator,
            description=description,
        )
        return self.repo.create_case(case)

    def list_cases(self) -> List[Dict[str, Any]]:
        """List all cases with evidence counts."""
        cases = self.repo.list_cases()
        summary = []
        for c in cases:
            evidence_list = self.repo.list_evidence(c.case_id)
            summary.append({
                "case_id": c.case_id,
                "title": c.title,
                "investigator": c.investigator,
                "status": c.status,
                "created_at_utc": c.created_at_utc,
                "evidence_count": len(evidence_list),
            })
        return summary

    def get_case_details(self, case_id: str) -> Dict[str, Any]:
        """Retrieve full case details, evidence items, notes, and audit logs."""
        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' was not found.")

        evidence_items = self.repo.list_evidence(case_id)
        audit_logs = self.repo.list_audit_logs(case_id)
        notes = self.repo.list_notes(case_id)

        return {
            "case": case,
            "evidence": evidence_items,
            "audit_logs": audit_logs,
            "notes": notes,
            "tamper_notice": "Note: Local SQLite audit records are not independently tamper-proof (e.g., WORM/blockchain).",
        }

    def acquire_evidence(
        self,
        case_id: str,
        source_path: str | Path,
        actor: str = "Investigator",
        notes: Optional[str] = None
    ) -> EvidenceItem:
        """
        Acquire a file as evidence into the case vault:
        1. Hash original at acquisition (SHA256, SHA512, MD5).
        2. Copy working copy to case vault without altering original.
        3. Set read-only permissions on vault copy (0o444).
        4. Log to audit trail.
        """
        src = validate_file_path(source_path, must_exist=True)
        if not src.is_file():
            raise ValueError(f"Evidence target '{src}' must be a regular file.")

        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' does not exist.")

        # Compute initial acquisition hashes
        digests = calculate_hashes(src, algorithms=["sha256", "sha512", "md5"])
        file_info = inspect_file(src)

        evidence_id = f"EV-{uuid.uuid4().hex[:8].upper()}"
        vault_dir = get_cases_dir() / case_id / "evidence"
        vault_dir.mkdir(parents=True, exist_ok=True)

        vault_filename = f"{evidence_id}_{src.name}"
        vault_path = vault_dir / vault_filename

        # Copy to vault
        shutil.copy2(src, vault_path)

        # Set read-only protection (0o444)
        try:
            os.chmod(vault_path, 0o444)
        except OSError:
            pass  # Some filesystems (e.g. FAT32/exFAT) may ignore chmod

        now_utc = datetime.now(timezone.utc).isoformat()
        evidence_item = EvidenceItem(
            evidence_id=evidence_id,
            case_id=case_id,
            original_path=str(src),
            vault_path=str(vault_path),
            file_name=src.name,
            file_size_bytes=src.stat().st_size,
            detected_format=file_info["detected_format"],
            sha256_at_acquisition=digests["sha256"],
            sha512_at_acquisition=digests["sha512"],
            md5_legacy=digests["md5"],
            acquisition_utc=now_utc,
            last_verified_utc=now_utc,
            integrity_status="VERIFIED_AT_ACQUISITION",
            notes=notes,
        )

        return self.repo.add_evidence(evidence_item, actor=actor)

    def verify_case_integrity(self, case_id: str, actor: str = "Investigator") -> Dict[str, Any]:
        """
        Re-verify hashes of all evidence artifacts in a case against their acquisition hashes.
        Clearly documents verified and failed items.
        """
        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' does not exist.")

        evidence_items = self.repo.list_evidence(case_id)
        results = []
        all_passed = True
        now_utc = datetime.now(timezone.utc).isoformat()

        for item in evidence_items:
            v_path = Path(item.vault_path)
            if not v_path.exists():
                status = "FAILED_FILE_MISSING"
                all_passed = False
                self.repo.update_evidence_verification(item.evidence_id, status, now_utc)
                self.repo.add_audit_log(
                    AuditLog(
                        id=None,
                        case_id=case_id,
                        action="INTEGRITY_VERIFICATION_FAILED",
                        actor=actor,
                        details=f"Evidence {item.evidence_id} missing from vault at {v_path}",
                        timestamp_utc=now_utc,
                    )
                )
                results.append({
                    "evidence_id": item.evidence_id,
                    "file_name": item.file_name,
                    "status": status,
                    "error": "Vault file missing"
                })
                continue

            current_hashes = calculate_hashes(v_path, algorithms=["sha256"])
            current_sha256 = current_hashes["sha256"]

            if current_sha256 == item.sha256_at_acquisition:
                status = "INTEGRITY_VERIFIED"
                self.repo.update_evidence_verification(item.evidence_id, status, now_utc)
                self.repo.add_audit_log(
                    AuditLog(
                        id=None,
                        case_id=case_id,
                        action="INTEGRITY_VERIFIED",
                        actor=actor,
                        details=f"Evidence {item.evidence_id} SHA256 matches acquisition digest.",
                        timestamp_utc=now_utc,
                    )
                )
                results.append({
                    "evidence_id": item.evidence_id,
                    "file_name": item.file_name,
                    "status": status,
                    "sha256": current_sha256,
                })
            else:
                status = "FAILED_INTEGRITY_MISMATCH"
                all_passed = False
                self.repo.update_evidence_verification(item.evidence_id, status, now_utc)
                self.repo.add_audit_log(
                    AuditLog(
                        id=None,
                        case_id=case_id,
                        action="INTEGRITY_FAILED_TAMPER_ALERT",
                        actor=actor,
                        details=(
                            f"Evidence {item.evidence_id} digest mismatch! "
                            f"Expected: {item.sha256_at_acquisition}, Got: {current_sha256}"
                        ),
                        timestamp_utc=now_utc,
                    )
                )
                results.append({
                    "evidence_id": item.evidence_id,
                    "file_name": item.file_name,
                    "status": status,
                    "expected_sha256": item.sha256_at_acquisition,
                    "current_sha256": current_sha256,
                })

        return {
            "case_id": case_id,
            "verification_timestamp_utc": now_utc,
            "overall_integrity_passed": all_passed,
            "total_items_checked": len(evidence_items),
            "results": results,
        }

    def add_case_note(self, case_id: str, author: str, content: str) -> CaseNote:
        """Add an investigator note to a case."""
        case = self.repo.get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case '{case_id}' does not exist.")

        note = CaseNote(
            id=None,
            case_id=case_id,
            author=author,
            content=content,
        )
        return self.repo.add_note(note)
