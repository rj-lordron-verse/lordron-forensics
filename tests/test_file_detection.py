"""
Unit tests for file intelligence, magic byte detection, and anomaly alerts.
"""

from lordron.core.file_detection import inspect_file
from lordron.modules.file_intelligence.inspector import batch_inspect_directory, compare_two_files


def test_detect_pdf_signature(tmp_path):
    pdf = tmp_path / "document.pdf"
    pdf.write_bytes(b"%PDF-1.7\n%synthetic test content\n")

    info = inspect_file(pdf)
    assert info["detected_format"] == "PDF Document"
    assert info["mime_type"] == "application/pdf"
    assert info["known_signature"] is True
    assert info["suspicious_mismatch"] is False


def test_detect_suspicious_extension_mismatch(sample_mismatched_file):
    info = inspect_file(sample_mismatched_file)
    assert "ELF" in info["detected_format"]
    assert info["suspicious_mismatch"] is True
    assert "Expected one of" in info["mismatch_details"]


def test_batch_inspect_and_deduplication(tmp_path):
    d = tmp_path / "investigation_dump"
    d.mkdir()

    # Create two identical files with different names
    content = b"Duplicated Evidence Block 99"
    (d / "item_a.bin").write_bytes(content)
    (d / "item_b.bin").write_bytes(content)
    (d / "item_c.txt").write_text("Unique File")

    batch = batch_inspect_directory(d)
    assert batch["total_files_scanned"] == 3
    assert batch["duplicate_groups_found"] == 1


def test_compare_two_files(tmp_path):
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"
    f3 = tmp_path / "file3.txt"

    f1.write_text("Hello World")
    f2.write_text("Hello World")
    f3.write_text("Different Content")

    res_same = compare_two_files(f1, f2)
    assert res_same["identical_content"] is True

    res_diff = compare_two_files(f1, f3)
    assert res_diff["identical_content"] is False
