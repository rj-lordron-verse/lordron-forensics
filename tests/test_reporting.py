"""
Unit tests for HTML, JSON, and CSV report generation.
"""

from lordron.modules.reporting.generator import ReportGenerator


def test_generate_all_report_formats(evidence_mgr, sample_text_file):
    evidence_mgr.create_case("CASE-REP", title="Report Generation Test", investigator="Raj")
    evidence_mgr.acquire_evidence("CASE-REP", sample_text_file)
    evidence_mgr.add_case_note("CASE-REP", author="Raj", content="Primary triage complete.")

    gen = ReportGenerator(repo=evidence_mgr.repo)

    # 1. HTML Report
    html_rep = gen.generate_report("CASE-REP", fmt="html")
    assert "<!DOCTYPE html>" in html_rep
    assert "LORDRON FORENSICS" in html_rep
    assert "CASE-REP" in html_rep
    assert "INTEGRITY VERIFIED" in html_rep

    # 2. JSON Report
    json_rep = gen.generate_report("CASE-REP", fmt="json")
    assert '"case_id": "CASE-REP"' in json_rep

    # 3. CSV Report
    csv_rep = gen.generate_report("CASE-REP", fmt="csv")
    assert "CASE-REP" in csv_rep
    assert "[EVIDENCE INVENTORY]" in csv_rep
    assert "[CASE TIMELINE]" in csv_rep
