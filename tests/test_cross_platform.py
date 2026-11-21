"""
Cross-platform compatibility unit tests for LORDRON Forensics.
Validates path security, platform-aware timestamps, subprocess encodings,
and environment diagnostics using synthetic mocks.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lordron.core.exceptions import FileAccessError
from lordron.core.file_detection import inspect_file
from lordron.core.paths import safe_relative_path, validate_file_path
from lordron.modules.diagnostics.doctor import (
    get_platform_flavor,
    run_system_diagnostics,
)
from lordron.modules.metadata_lab.exif_reader import extract_image_metadata
from lordron.modules.timeline.engine import TimelineEngine


# ------------------------------------------------------------------------------
# 1. Path & Drive Normalization Tests
# ------------------------------------------------------------------------------

def test_powershell_drag_drop_prefix_cleaned(tmp_path):
    target = tmp_path / "evidence_file.txt"
    target.write_text("sample evidence", encoding="utf-8")

    # Dragging and dropping a file in PowerShell can prefix '& "'
    raw_input = f'& "{target}"'
    validated = validate_file_path(raw_input, must_exist=True)
    assert validated == target.resolve()


def test_safe_relative_path_posix_valid(tmp_path):
    base = tmp_path / "case_vault"
    base.mkdir()
    target = base / "evidence.raw"
    target.write_bytes(b"data")

    res = safe_relative_path(target, base)
    assert res == target.resolve()


def test_safe_relative_path_posix_traversal_blocked(tmp_path):
    base = tmp_path / "case_vault"
    base.mkdir()
    outside = tmp_path / "unauthorized.txt"
    outside.write_text("secret")

    with pytest.raises(FileAccessError, match="Path traversal detected"):
        safe_relative_path(outside, base)


def test_safe_relative_path_windows_cross_drive_blocked():
    with patch("platform.system", return_value="Windows"):
        mock_target = MagicMock(spec=Path)
        mock_target.resolve.return_value = mock_target
        mock_target.drive = "D:"

        mock_base = MagicMock(spec=Path)
        mock_base.resolve.return_value = mock_base
        mock_base.drive = "C:"

        with pytest.raises(FileAccessError, match="on a different drive"):
            safe_relative_path(mock_target, mock_base)


def test_safe_relative_path_windows_case_insensitive():
    with patch("platform.system", return_value="Windows"):
        # Simulate Windows paths where casing differs across NTFS
        mock_target = MagicMock(spec=Path)
        mock_target.resolve.return_value = mock_target
        mock_target.drive = "C:"
        mock_target.relative_to.side_effect = ValueError("Case mismatch in path")
        mock_target.parts = ("C:", "Users", "Raj", "Cases", "Ev1")

        mock_base = MagicMock(spec=Path)
        mock_base.resolve.return_value = mock_base
        mock_base.drive = "c:"
        mock_base.parts = ("c:", "users", "raj", "cases")

        result = safe_relative_path(mock_target, mock_base)
        assert result == mock_target


# ------------------------------------------------------------------------------
# 2. Platform-Aware Timestamp Tests
# ------------------------------------------------------------------------------

def test_file_detection_inspect_windows_creation_time(tmp_path):
    f = tmp_path / "test_file.bin"
    f.write_bytes(b"data")

    with patch("platform.system", return_value="Windows"):
        info = inspect_file(f)
        assert "created_utc" in info["timestamps"]
        assert info["timestamps"]["created_utc"] == info["timestamps"]["created_or_metadata_changed_utc"]


def test_file_detection_inspect_macos_birthtime(tmp_path):
    f = tmp_path / "test_mac_file.bin"
    f.write_bytes(b"data")

    real_stat = f.stat()

    class MockStat:
        st_size = real_stat.st_size
        st_mtime = real_stat.st_mtime
        st_ctime = real_stat.st_ctime
        st_atime = real_stat.st_atime
        st_birthtime = 1711700000.0  # Synthetic birthtime

    with patch.object(Path, "stat", return_value=MockStat()):
        info = inspect_file(f)
        assert "birthtime_utc" in info["timestamps"]


def test_timeline_engine_windows_ctime_label(evidence_mgr, sample_text_file):
    evidence_mgr.create_case("CASE-WIN-TL", title="Windows Timeline")
    evidence_mgr.acquire_evidence("CASE-WIN-TL", sample_text_file)

    with patch("platform.system", return_value="Windows"):
        engine = TimelineEngine(repo=evidence_mgr.repo)
        tl = engine.build_case_timeline("CASE-WIN-TL")

        ctime_events = [ev for ev in tl["events"] if ev["source_type"] == "FILESYSTEM_CTIME"]
        assert len(ctime_events) > 0
        assert "Windows ctime" in ctime_events[0]["summary"]


def test_timeline_engine_posix_ctime_label(evidence_mgr, sample_text_file):
    evidence_mgr.create_case("CASE-POSIX-TL", title="POSIX Timeline")
    evidence_mgr.acquire_evidence("CASE-POSIX-TL", sample_text_file)

    with patch("platform.system", return_value="Linux"):
        engine = TimelineEngine(repo=evidence_mgr.repo)
        tl = engine.build_case_timeline("CASE-POSIX-TL")

        ctime_events = [ev for ev in tl["events"] if ev["source_type"] == "FILESYSTEM_CTIME"]
        assert len(ctime_events) > 0
        assert "POSIX ctime" in ctime_events[0]["summary"]


def test_timeline_engine_macos_birthtime_event(evidence_mgr, sample_text_file):
    evidence_mgr.create_case("CASE-MAC-TL", title="macOS Timeline")
    item = evidence_mgr.acquire_evidence("CASE-MAC-TL", sample_text_file)

    vault_p = Path(item.vault_path)
    real_stat = vault_p.stat()

    class MockMacStat:
        st_size = real_stat.st_size
        st_mtime = real_stat.st_mtime
        st_ctime = real_stat.st_ctime
        st_birthtime = 1711700000.0

    with patch.object(Path, "stat", return_value=MockMacStat()):
        engine = TimelineEngine(repo=evidence_mgr.repo)
        tl = engine.build_case_timeline("CASE-MAC-TL")

        birth_events = [ev for ev in tl["events"] if ev["source_type"] == "FILESYSTEM_BIRTHTIME"]
        assert len(birth_events) > 0
        assert "macOS/BSD" in birth_events[0]["summary"]


# ------------------------------------------------------------------------------
# 3. ExifTool Graceful Fallback & UTF-8 Subprocess Tests
# ------------------------------------------------------------------------------

def test_exiftool_missing_graceful_handling(tmp_path):
    img_path = tmp_path / "sample.jpg"
    img_path.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00")

    with patch("shutil.which", return_value=None):
        data = extract_image_metadata(img_path, use_exiftool_if_available=True)
        assert data["exiftool_output"] is None
        assert "exiftool_note" in data
        assert "not found in PATH" in data["exiftool_note"]


def test_exiftool_utf8_subprocess_decoding(tmp_path):
    img_path = tmp_path / "international_sample.jpg"
    img_path.write_bytes(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00")

    mock_json_out = '[{"SourceFile": "test.jpg", "Make": "富士フイルム", "Model": "X-T4", "Artist": "München Investigator"}]'
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = mock_json_out

    with patch("shutil.which", return_value="/usr/bin/exiftool"), \
         patch("subprocess.run", return_value=mock_proc) as mock_sub:
        data = extract_image_metadata(img_path, use_exiftool_if_available=True)

        assert mock_sub.called
        kwargs = mock_sub.call_args[1]
        assert kwargs.get("encoding") == "utf-8"
        assert kwargs.get("errors") == "replace"

        assert data["exiftool_output"] is not None
        assert data["exiftool_output"]["Make"] == "富士フイルム"
        assert data["exiftool_output"]["Artist"] == "München Investigator"


# ------------------------------------------------------------------------------
# 4. Platform Diagnostics & Package Manager Matrix Tests
# ------------------------------------------------------------------------------

@pytest.mark.parametrize("sys_val,is_term,is_wsl_val,expected_plat,expected_pkg", [
    ("Linux", True, False, "Android Termux", "pkg"),
    ("Linux", False, True, "Windows Subsystem for Linux (WSL)", "apt/dnf"),
    ("Darwin", False, False, "macOS", "brew"),
    ("Windows", False, False, "Windows", "winget/choco"),
    ("Linux", False, False, "Linux", "apt/dnf/pacman"),
])
def test_platform_flavor_detection(sys_val, is_term, is_wsl_val, expected_plat, expected_pkg):
    with patch("platform.system", return_value=sys_val), \
         patch("lordron.modules.diagnostics.doctor.is_termux", return_value=is_term), \
         patch("lordron.modules.diagnostics.doctor.is_wsl", return_value=is_wsl_val):
        flavor = get_platform_flavor()
        assert flavor["platform_name"] == expected_plat
        assert flavor["package_manager"] == expected_pkg


def test_doctor_diagnostics_includes_platform_recommendations():
    diag = run_system_diagnostics()
    assert "package_recommendations" in diag
    assert "platform_name" in diag["system"]
    assert "package_manager" in diag["system"]


# ------------------------------------------------------------------------------
# 5. Installer Script Validation Tests
# ------------------------------------------------------------------------------

def test_install_ps1_contains_all_phases():
    ps1_path = Path(__file__).resolve().parent.parent / "install.ps1"
    assert ps1_path.exists(), "install.ps1 must exist in the root repository"

    content = ps1_path.read_text(encoding="utf-8")
    # Verify key cross-platform phases exist
    assert "Detecting Windows host operating system" in content
    assert "Checking Python runtime compatibility" in content
    assert "Setting up isolated Python virtual environment" in content
    assert "Installing core dependencies" in content
    assert "Installing LORDRON Forensics in editable mode" in content
    assert "Verifying CLI command execution" in content
    assert "winget install OliverBetz.ExifTool" in content
    assert "Set-ExecutionPolicy" in content
    assert "Activate.ps1" in content
