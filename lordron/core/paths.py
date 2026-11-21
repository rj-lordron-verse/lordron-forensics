"""
Filesystem path utilities and security controls for LORDRON Forensics.
"""

from __future__ import annotations
import os
import platform
from pathlib import Path
from lordron.core.exceptions import FileAccessError


def get_base_dir() -> Path:
    """Return the base storage directory for LORDRON cases and configuration."""
    custom = os.environ.get("LORDRON_HOME")
    if custom:
        base = Path(custom).expanduser().resolve()
    else:
        base = Path.home() / ".lordron"
    base.mkdir(parents=True, exist_ok=True)
    return base


def get_cases_dir() -> Path:
    """Return the directory where local forensic cases are maintained."""
    cases_dir = get_base_dir() / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)
    return cases_dir


def get_database_path() -> Path:
    """Return the primary SQLite database path."""
    return get_base_dir() / "lordron_cases.db"


def validate_file_path(path_str: str | Path, must_exist: bool = True) -> Path:
    """
    Safely resolve and validate a file path.
    Prevents path traversal and checks file access permissions.
    Cleans quotation marks, surrounding whitespace, and PowerShell '& ' drag-drop prefixes.
    """
    try:
        clean_str = str(path_str).strip().strip("'\"")
        # Handle PowerShell '& "C:\path"' artifacts from drag-and-drop
        if clean_str.startswith("& "):
            clean_str = clean_str[2:].strip().strip("'\"")
        p = Path(clean_str).expanduser().resolve()
    except Exception as exc:
        raise FileAccessError(f"Invalid path representation: {exc}") from exc

    if must_exist:
        if not p.exists():
            raise FileAccessError(f"File or directory not found: {p}")
        if not os.access(p, os.R_OK):
            raise FileAccessError(f"Permission denied: cannot read '{p}'")
    return p


def safe_relative_path(target: Path, base: Path) -> Path:
    """Verify target is strictly inside base to guard against directory traversal."""
    resolved_target = target.resolve()
    resolved_base = base.resolve()

    # On Windows, drive letters can differ and filesystems are case-insensitive
    if platform.system() == "Windows" or os.name == "nt":
        if getattr(resolved_target, "drive", "").lower() != getattr(resolved_base, "drive", "").lower():
            raise FileAccessError(f"Path traversal detected: {target} is on a different drive than {base}")
        try:
            resolved_target.relative_to(resolved_base)
            return resolved_target
        except ValueError:
            # Case-folded traversal verification for Windows NTFS/FAT
            t_parts = [p.lower() for p in resolved_target.parts]
            b_parts = [p.lower() for p in resolved_base.parts]
            if len(t_parts) >= len(b_parts) and t_parts[:len(b_parts)] == b_parts:
                return resolved_target
            raise FileAccessError(f"Path traversal detected: {target} is outside {base}")
    else:
        try:
            resolved_target.relative_to(resolved_base)
            return resolved_target
        except ValueError as exc:
            raise FileAccessError(f"Path traversal detected: {target} is outside {base}") from exc
