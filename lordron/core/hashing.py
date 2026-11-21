"""
Cryptographic hashing engine with chunked streaming for LORDRON Forensics.
Calculates SHA256, SHA512, SHA1, and legacy MD5 with zero file modification.
"""

from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
from lordron.core.paths import validate_file_path
from lordron.core.exceptions import FileAccessError

CHUNK_SIZE = 1024 * 1024  # 1 MB chunk for streaming efficiency


def calculate_hashes(
    file_path: str | Path,
    algorithms: Optional[list[str]] = None,
    chunk_size: int = CHUNK_SIZE
) -> Dict[str, str]:
    """
    Stream and calculate cryptographic digests for a target file.
    Default algorithms: sha256, sha512, sha1, md5 (legacy).
    """
    path = validate_file_path(file_path, must_exist=True)
    if not path.is_file():
        raise FileAccessError(f"Target '{path}' is not a regular file.")

    if algorithms is None:
        algorithms = ["sha256", "sha512", "sha1", "md5"]

    hashers = {algo.lower(): getattr(hashlib, algo.lower())() for algo in algorithms}

    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                for h in hashers.values():
                    h.update(chunk)
    except OSError as exc:
        raise FileAccessError(f"Error reading file '{path}' during hash calculation: {exc}") from exc

    return {algo: h.hexdigest().lower() for algo, h in hashers.items()}


def verify_hash(file_path: str | Path, expected_hash: str) -> Dict[str, Any]:
    """
    Verify file integrity against an expected hash value.
    Auto-detects algorithm based on hex length (32=MD5, 40=SHA1, 64=SHA256, 128=SHA512).
    """
    expected = expected_hash.strip().lower()
    length = len(expected)

    algo_map = {
        32: "md5",
        40: "sha1",
        64: "sha256",
        128: "sha512"
    }

    algo = algo_map.get(length)
    if not algo:
        raise ValueError(
            f"Unable to determine hash algorithm for digest length {length}. "
            "Supported lengths: 32 (MD5), 40 (SHA1), 64 (SHA256), 128 (SHA512)."
        )

    computed_dict = calculate_hashes(file_path, algorithms=[algo])
    computed_digest = computed_dict[algo]
    is_match = (computed_digest == expected)

    return {
        "file": str(file_path),
        "algorithm": algo.upper(),
        "expected": expected,
        "calculated": computed_digest,
        "matched": is_match,
        "status": "VERIFIED" if is_match else "FAILED_INTEGRITY_MISMATCH"
    }
