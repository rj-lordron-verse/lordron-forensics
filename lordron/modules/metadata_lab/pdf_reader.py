"""
PDF document metadata extraction with pypdf and pure-Python binary fallback.
"""

from __future__ import annotations
import logging
import re
from pathlib import Path
from typing import Dict, Any
from lordron.core.paths import validate_file_path

try:
    import pypdf
    PYPDF_AVAILABLE = True
    logging.getLogger("pypdf").setLevel(logging.ERROR)
except ImportError:
    PYPDF_AVAILABLE = False


def _parse_pdf_date(date_str: str) -> str:
    """Format PDF date strings like D:20240101120000Z to standard representation."""
    if not date_str:
        return ""
    clean = date_str.replace("D:", "")
    # Extract YYYY-MM-DD HH:MM:SS if long enough
    if len(clean) >= 14:
        return f"{clean[0:4]}-{clean[4:6]}-{clean[6:8]} {clean[8:10]}:{clean[10:12]}:{clean[12:14]} UTC"
    return clean


def extract_pdf_metadata(file_path: str | Path) -> Dict[str, Any]:
    """Extract document properties and metadata from PDF files."""
    path = validate_file_path(file_path, must_exist=True)

    result: Dict[str, Any] = {
        "file_name": path.name,
        "format_category": "DOCUMENT_PDF",
        "has_metadata": False,
        "page_count": None,
        "is_encrypted": False,
        "properties": {},
        "parser_used": None,
    }

    if PYPDF_AVAILABLE:
        try:
            reader = pypdf.PdfReader(str(path), strict=False)
            result["parser_used"] = "pypdf"
            result["page_count"] = len(reader.pages)
            result["is_encrypted"] = reader.is_encrypted

            meta = reader.metadata
            if meta:
                result["has_metadata"] = True
                result["properties"] = {
                    "title": meta.title or "(None)",
                    "author": meta.author or "(None)",
                    "subject": meta.subject or "(None)",
                    "creator": meta.creator or "(None)",
                    "producer": meta.producer or "(None)",
                    "creation_date": _parse_pdf_date(str(meta.creation_date or "")),
                    "modification_date": _parse_pdf_date(str(meta.modification_date or "")),
                }
            return result
        except Exception:
            pass  # Fallback to binary regex parser below

    # Pure Python binary regex fallback parser for PDF trailer / Info dictionaries
    try:
        with open(path, "rb") as f:
            content = f.read(512 * 1024)  # Read first 512KB and last 512KB
            if path.stat().st_size > 1024 * 1024:
                f.seek(-512 * 1024, 2)
                content += f.read(512 * 1024)

        result["parser_used"] = "lordron_native_binary_parser"
        text_content = content.decode("latin-1", errors="ignore")

        # Check encryption
        if "/Encrypt" in text_content:
            result["is_encrypted"] = True

        # Extract Info fields
        fields = ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate"]
        extracted: Dict[str, str] = {}

        for field in fields:
            # Pattern matches /Title (value) or /Title <hex>
            m = re.search(rf"/{field}\s*\((.*?)\)", text_content)
            if m:
                extracted[field.lower()] = m.group(1).strip()
            else:
                m_hex = re.search(rf"/{field}\s*<([0-9a-fA-F]+)>", text_content)
                if m_hex:
                    try:
                        extracted[field.lower()] = bytes.fromhex(m_hex.group(1)).decode("latin-1", errors="replace")
                    except Exception:
                        extracted[field.lower()] = m_hex.group(1)

        # Estimate page count
        pages_matches = re.findall(r"/Type\s*/Page\b", text_content)
        if pages_matches:
            result["page_count"] = len(pages_matches)

        if extracted:
            result["has_metadata"] = True
            result["properties"] = extracted
        else:
            result["has_metadata"] = False
            result["properties"] = {"status": "NO_EMBEDDED_METADATA_FOUND"}

    except Exception as exc:
        result["error"] = f"Failed to parse PDF metadata: {exc}"

    return result
