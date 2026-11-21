"""
Module 02: Metadata Lab
Unified dispatcher for extracting and comparing metadata from images, documents, and files.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any
from lordron.core.paths import validate_file_path
from lordron.core.file_detection import inspect_file
from lordron.modules.metadata_lab.exif_reader import extract_image_metadata
from lordron.modules.metadata_lab.pdf_reader import extract_pdf_metadata


def inspect_metadata(file_path: str | Path, use_exiftool: bool = False) -> Dict[str, Any]:
    """Inspect all available embedded and structural metadata from a file."""
    path = validate_file_path(file_path, must_exist=True)
    file_info = inspect_file(path)

    mime = file_info["mime_type"].lower()
    ext = path.suffix.lower()

    if mime.startswith("image/") or ext in [".jpg", ".jpeg", ".png", ".tiff", ".webp", ".gif"]:
        meta = extract_image_metadata(path, use_exiftool_if_available=use_exiftool)
    elif mime == "application/pdf" or ext == ".pdf":
        meta = extract_pdf_metadata(path)
    else:
        meta = {
            "file_name": path.name,
            "format_category": "GENERAL_FILE",
            "has_metadata": False,
            "note": "No specialized metadata extractor for this file type; showing filesystem properties.",
            "properties": {
                "detected_format": file_info["detected_format"],
                "mime_type": file_info["mime_type"],
                "file_size_bytes": file_info["file_size_bytes"],
                "timestamps": file_info["timestamps"],
            }
        }

    meta["file_inspection"] = file_info
    return meta


def compare_metadata(file1: str | Path, file2: str | Path) -> Dict[str, Any]:
    """Compare metadata properties between two files."""
    m1 = inspect_metadata(file1)
    m2 = inspect_metadata(file2)

    return {
        "file1": m1,
        "file2": m2,
        "comparison_summary": {
            "file1_name": m1["file_name"],
            "file2_name": m2["file_name"],
            "format1": m1.get("format_category"),
            "format2": m2.get("format_category"),
            "both_have_metadata": bool(m1.get("has_exif") or m1.get("has_metadata")) and bool(m2.get("has_exif") or m2.get("has_metadata")),
        }
    }
