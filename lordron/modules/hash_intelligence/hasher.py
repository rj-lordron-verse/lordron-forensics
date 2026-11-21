"""
Module 03: Hash Intelligence
Cryptographic digests, batch calculation, and integrity verification.
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, List
from lordron.core.paths import validate_file_path
from lordron.core.hashing import calculate_hashes, verify_hash
from lordron.core.exceptions import FileAccessError


def hash_single_file(file_path: str | Path) -> Dict[str, Any]:
    """Calculate standard and legacy hashes for a single file."""
    path = validate_file_path(file_path, must_exist=True)
    digests = calculate_hashes(path)
    return {
        "file_name": path.name,
        "absolute_path": str(path),
        "file_size_bytes": path.stat().st_size,
        "hashes": {
            "sha256": digests["sha256"],
            "sha512": digests["sha512"],
            "sha1": digests["sha1"],
            "md5_legacy": digests["md5"],
        },
        "note": "MD5 is included strictly for legacy forensic identification and cataloging."
    }


def hash_directory_batch(directory_path: str | Path, recursive: bool = True) -> Dict[str, Any]:
    """Calculate hashes for all files within a directory in batch."""
    dir_path = validate_file_path(directory_path, must_exist=True)
    if not dir_path.is_dir():
        raise FileAccessError(f"Target '{dir_path}' is not a directory.")

    pattern = "**/*" if recursive else "*"
    results: List[Dict[str, Any]] = []

    for item in dir_path.glob(pattern):
        if item.is_file() and not item.is_symlink():
            try:
                res = hash_single_file(item)
                results.append(res)
            except Exception as exc:
                results.append({
                    "file_name": item.name,
                    "absolute_path": str(item),
                    "error": str(exc),
                })

    return {
        "directory": str(dir_path),
        "total_files": len(results),
        "files": results,
    }


def verify_file_integrity(file_path: str | Path, expected_hash: str) -> Dict[str, Any]:
    """Verify cryptographic integrity of a file against an expected digest."""
    return verify_hash(file_path, expected_hash)
