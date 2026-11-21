"""
Module 09: System Diagnostics
Verifies system health, environment prerequisites, dependencies, and database integrity.
Never exposes sensitive environment variables or credentials.
"""

from __future__ import annotations
import os
import sys
import shutil
import platform
import sqlite3
from pathlib import Path
from typing import Dict, Any
from lordron.core.paths import get_base_dir, get_database_path, get_cases_dir


def is_termux() -> bool:
    """Detect if running inside an Android Termux environment."""
    return "com.termux" in os.environ.get("PREFIX", "") or "com.termux" in str(Path.home())


def is_wsl() -> bool:
    """Detect if running inside Windows Subsystem for Linux."""
    if "WSL_DISTRO_NAME" in os.environ:
        return True
    try:
        proc_ver = Path("/proc/version")
        if proc_ver.exists():
            return "microsoft" in proc_ver.read_text().lower()
    except Exception:
        pass
    return False


def get_platform_flavor() -> Dict[str, str]:
    """Detect platform family and recommended package manager for external forensic tools."""
    sys_name = platform.system()
    if is_termux():
        return {"platform_name": "Android Termux", "package_manager": "pkg"}
    if is_wsl():
        return {"platform_name": "Windows Subsystem for Linux (WSL)", "package_manager": "apt/dnf"}
    if sys_name == "Darwin":
        return {"platform_name": "macOS", "package_manager": "brew"}
    if sys_name == "Windows":
        return {"platform_name": "Windows", "package_manager": "winget/choco"}
    if sys_name == "Linux":
        return {"platform_name": "Linux", "package_manager": "apt/dnf/pacman"}
    return {"platform_name": sys_name, "package_manager": "native"}


def run_system_diagnostics() -> Dict[str, Any]:
    """Inspect environment, dependencies, filesystem permissions, and database health."""
    # 1. Environment & Python
    py_ver = sys.version_info
    py_compatible = (py_ver.major == 3 and py_ver.minor >= 11)

    # 2. Storage
    base_dir = get_base_dir()
    disk_total, disk_used, disk_free = shutil.disk_usage(base_dir)

    # 3. Dependencies
    def _check_dep(mod_name: str) -> bool:
        try:
            __import__(mod_name)
            return True
        except ImportError:
            return False

    dependencies = {
        "sqlite3 (built-in)": _check_dep("sqlite3"),
        "hashlib (built-in)": _check_dep("hashlib"),
        "rich": _check_dep("rich"),
        "typer": _check_dep("typer"),
        "Pillow": _check_dep("PIL"),
    }

    optional_tools = {
        "pypdf": _check_dep("pypdf"),
        "exiftool (CLI binary)": shutil.which("exiftool") is not None,
        "pytest (dev)": _check_dep("pytest"),
        "ruff (dev)": shutil.which("ruff") is not None,
    }

    # 4. Database health
    db_path = get_database_path()
    db_status = "NOT_INITIALIZED"
    table_counts = {}

    if db_path.exists():
        try:
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA quick_check;")
                check_result = cursor.fetchone()[0]
                if check_result == "ok":
                    db_status = "HEALTHY"
                    for tbl in ["cases", "evidence", "audit_logs", "case_notes"]:
                        try:
                            cursor.execute(f"SELECT COUNT(*) FROM {tbl};")
                            table_counts[tbl] = cursor.fetchone()[0]
                        except sqlite3.OperationalError:
                            table_counts[tbl] = 0
                else:
                    db_status = f"INTEGRITY_CHECK_FAILED: {check_result}"
        except Exception as exc:
            db_status = f"ERROR: {exc}"

    # Overall system health flag
    core_deps_ok = all(dependencies.values())
    overall_health = py_compatible and core_deps_ok and (db_status in ["HEALTHY", "NOT_INITIALIZED"])

    flavor = get_platform_flavor()
    recommendations: Dict[str, str] = {}
    if not optional_tools["pypdf"]:
        recommendations["pypdf"] = "pip install pypdf"
    if not optional_tools["exiftool (CLI binary)"]:
        if flavor["platform_name"] == "Android Termux":
            recommendations["exiftool"] = "pkg install exiftool"
        elif flavor["platform_name"] == "macOS":
            recommendations["exiftool"] = "brew install exiftool"
        elif flavor["platform_name"] == "Windows":
            recommendations["exiftool"] = "winget install OliverBetz.ExifTool (or choco install exiftool)"
        else:
            recommendations["exiftool"] = "sudo apt install -y libimage-exiftool-perl (or dnf install perl-Image-ExifTool)"
    if not optional_tools["pytest (dev)"]:
        recommendations["pytest"] = "pip install pytest"
    if not optional_tools["ruff (dev)"]:
        if flavor["platform_name"] == "Android Termux":
            recommendations["ruff"] = "pkg install ruff"
        else:
            recommendations["ruff"] = "pip install ruff"

    return {
        "lordron_version": "1.0.0",
        "author": "Raj",
        "brand": "LORDRON",
        "overall_health": "OPTIMAL" if overall_health else "DEGRADED",
        "system": {
            "os": platform.system(),
            "platform_name": flavor["platform_name"],
            "package_manager": flavor["package_manager"],
            "release": platform.release(),
            "architecture": platform.machine(),
            "is_termux": is_termux(),
            "is_wsl": is_wsl(),
            "python_version": f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}",
            "python_compatible_3_11_plus": py_compatible,
        },
        "storage": {
            "base_directory": str(base_dir),
            "cases_directory": str(get_cases_dir()),
            "disk_free_gb": round(disk_free / (1024 ** 3), 2),
            "disk_total_gb": round(disk_total / (1024 ** 3), 2),
            "writable": os.access(base_dir, os.W_OK),
        },
        "dependencies": dependencies,
        "optional_tools": optional_tools,
        "package_recommendations": recommendations,
        "database": {
            "path": str(db_path),
            "status": db_status,
            "table_records": table_counts,
        }
    }
