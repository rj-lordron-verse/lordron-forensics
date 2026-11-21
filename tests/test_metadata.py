"""
Unit tests for metadata extraction, missing metadata handling, and PDF parsing.
"""

from lordron.modules.metadata_lab.inspector import inspect_metadata
from lordron.modules.metadata_lab.pdf_reader import extract_pdf_metadata

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


def test_pdf_metadata_extraction(tmp_path):
    pdf = tmp_path / "test_doc.pdf"
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Title (Confidential Memo) /Author (Raj) >>\nendobj\n"
        b"trailer\n<< /Info 1 0 R >>\n%%EOF"
    )
    pdf.write_bytes(pdf_content)

    meta = extract_pdf_metadata(pdf)
    assert meta["format_category"] == "DOCUMENT_PDF"
    assert meta["has_metadata"] is True
    assert meta["properties"].get("title") == "Confidential Memo"
    assert meta["properties"].get("author") == "Raj"


def test_missing_metadata_never_fabricates(tmp_path):
    txt = tmp_path / "plain.txt"
    txt.write_text("Standard log text without any embedded EXIF.")

    meta = inspect_metadata(txt)
    assert meta["has_metadata"] is False
    assert "No specialized metadata extractor" in meta["note"]


def test_synthetic_image_metadata(tmp_path):
    if not PILLOW_AVAILABLE:
        return

    img_path = tmp_path / "test.png"
    img = Image.new("RGB", (100, 100), color="blue")
    img.save(img_path)

    meta = inspect_metadata(img_path)
    assert meta["format_category"] == "IMAGE"
    assert meta["dimensions"]["width"] == 100
    assert meta["dimensions"]["height"] == 100
    assert meta["gps"]["status"] == "NOT_PRESENT"
