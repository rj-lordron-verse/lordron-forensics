"""
Unit tests for evidence acquisition, vault preservation, SQLite custody, and integrity audits.
"""

import os
from pathlib import Path
import pytest
from lordron.core.exceptions import CaseAlreadyExistsError


def test_create_case_and_persistence(evidence_mgr):
    case = evidence_mgr.create_case(
        case_id="CASE-2026-001",
        title="Operation Silent Watch",
        investigator="Raj",
        description="Forensic examination of compromised host."
    )
    assert case.case_id == "CASE-2026-001"

    cases = evidence_mgr.list_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == "CASE-2026-001"


def test_duplicate_case_id_rejected(evidence_mgr):
    evidence_mgr.create_case(case_id="CASE-DUP")
    with pytest.raises(CaseAlreadyExistsError):
        evidence_mgr.create_case(case_id="CASE-DUP")


def test_evidence_acquisition_and_vault_protection(evidence_mgr, sample_text_file):
    evidence_mgr.create_case(case_id="CASE-ACQ", investigator="Raj")

    item = evidence_mgr.acquire_evidence(
        case_id="CASE-ACQ",
        source_path=sample_text_file,
        notes="Recovered from investigator desk"
    )

    assert item.evidence_id.startswith("EV-")
    assert item.file_name == "notes.txt"
    assert len(item.sha256_at_acquisition) == 64
    assert Path(item.vault_path).exists()


def test_integrity_verification_pass(evidence_mgr, sample_text_file):
    evidence_mgr.create_case(case_id="CASE-PASS")
    _ = evidence_mgr.acquire_evidence("CASE-PASS", sample_text_file)

    verify_res = evidence_mgr.verify_case_integrity("CASE-PASS")
    assert verify_res["overall_integrity_passed"] is True
    assert verify_res["results"][0]["status"] == "INTEGRITY_VERIFIED"


def test_integrity_verification_tamper_detection(evidence_mgr, sample_text_file):
    evidence_mgr.create_case(case_id="CASE-TAMPER")
    item = evidence_mgr.acquire_evidence("CASE-TAMPER", sample_text_file)

    # Simulate unauthorized tampering with vault file
    vault_p = Path(item.vault_path)
    os.chmod(vault_p, 0o666)
    with open(vault_p, "a") as f:
        f.write("\nMALICIOUS_INJECTED_DATA")

    verify_res = evidence_mgr.verify_case_integrity("CASE-TAMPER")
    assert verify_res["overall_integrity_passed"] is False
    assert verify_res["results"][0]["status"] == "FAILED_INTEGRITY_MISMATCH"


def test_case_notes_and_audit(evidence_mgr):
    evidence_mgr.create_case(case_id="CASE-NOTES")
    note = evidence_mgr.add_case_note(
        case_id="CASE-NOTES",
        author="Raj",
        content="Initial triage reveals no kernel rootkit."
    )
    assert note.id is not None

    details = evidence_mgr.get_case_details("CASE-NOTES")
    assert len(details["notes"]) == 1
    assert len(details["audit_logs"]) >= 2  # CASE_CREATED + NOTE_ADDED
