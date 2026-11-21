"""
Module 01: File Intelligence
Inspects magic signatures, MIME types, file sizes, timestamps, extension mismatches,
and detects duplicate files across directories.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List
from lordron.core.paths import validate_file_path
from lordron.core.file_detection import inspect_file
from lordron.core.hashing import calculate_hashes
from lordron.core.exceptions import FileAccessError


def inspect_single_file(file_path: str | Path) -> Dict[str, Any]:
    """Inspect a single file: format, size, timestamps, sha256, signature mismatch."""
    info = inspect_file(file_path)
    hashes = calculate_hashes(file_path, algorithms=["sha256"])
    info["sha256"] = hashes["sha256"]
    return info


def batch_inspect_directory(directory_path: str | Path, recursive: bool = True) -> Dict[str, Any]:
    """
    Inspect all files in a directory.
    Identifies format, signatures, suspicious extension mismatches,
    and detects duplicates grouped by cryptographic hash.
    """
    dir_path = validate_file_path(directory_path, must_exist=True)
    if not dir_path.is_dir():
        raise FileAccessError(f"Target '{dir_path}' is not a directory.")

    files: List[Dict[str, Any]] = []
    hash_map: Dict[str, List[str]] = {}
    suspicious_files: List[Dict[str, Any]] = []

    pattern = "**/*" if recursive else "*"
    for item in dir_path.glob(pattern):
        if item.is_file() and not item.is_symlink():
            try:
                res = inspect_single_file(item)
                files.append(res)
                h = res["sha256"]
                hash_map.setdefault(h, []).append(str(item))
                if res["suspicious_mismatch"]:
                    suspicious_files.append(res)
            except Exception as exc:
                files.append({
                    "file_name": item.name,
                    "absolute_path": str(item),
                    "error": str(exc),
                })

    # Group duplicates (hashes with > 1 file)
    duplicates = {
        h: file_list for h, file_list in hash_map.items() if len(file_list) > 1
    }

    return {
        "directory": str(dir_path),
        "total_files_scanned": len(files),
        "suspicious_mismatches_found": len(suspicious_files),
        "duplicate_groups_found": len(duplicates),
        "suspicious_files": suspicious_files,
        "duplicates": duplicates,
        "files": files,
    }


def compare_two_files(file1: str | Path, file2: str | Path) -> Dict[str, Any]:
    """Compare two files side-by-side for forensic differences."""
    info1 = inspect_single_file(file1)
    info2 = inspect_single_file(file2)

    identical_content = (info1["sha256"] == info2["sha256"])
    same_format = (info1["detected_format"] == info2["detected_format"])
    same_size = (info1["file_size_bytes"] == info2["file_size_bytes"])

    return {
        "file1": info1,
        "file2": info2,
        "identical_content": identical_content,
        "same_format": same_format,
        "same_size": same_size,
        "differences": {
            "format": None if same_format else f"'{info1['detected_format']}' vs '{info2['detected_format']}'",
            "size_bytes": None if same_size else f"{info1['file_size_bytes']} vs {info2['file_size_bytes']}",
            "sha256": None if identical_content else f"{info1['sha256']} vs {info2['sha256']}",
        }
    }
