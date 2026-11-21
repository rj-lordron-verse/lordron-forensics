"""
Unit tests for multi-source timeline engine and source distinction.
"""

from lordron.modules.timeline.engine import TimelineEngine


def test_timeline_source_distinction(evidence_mgr, sample_text_file):
    evidence_mgr.create_case("CASE-TL", title="Timeline Test")
    evidence_mgr.acquire_evidence("CASE-TL", sample_text_file)
    evidence_mgr.add_case_note("CASE-TL", author="Raj", content="Witness interviewed.")

    engine = TimelineEngine(repo=evidence_mgr.repo)
    tl = engine.build_case_timeline("CASE-TL")

    assert tl["total_events"] >= 4
    source_types = {ev["source_type"] for ev in tl["events"]}
    assert "CASE_CREATION" in source_types
    assert "EVIDENCE_ACQUISITION_UTC" in source_types
    assert "INVESTIGATOR_NOTE" in source_types
    assert "FILESYSTEM_MTIME" in source_types

    # Verify reliability warning is present on filesystem timestamps
    fs_events = [ev for ev in tl["events"] if "FILESYSTEM" in ev["source_type"]]
    assert len(fs_events) > 0
    for ev in fs_events:
        assert ev["reliability_warning"] is not None
        assert "timestomped" in ev["reliability_warning"]
