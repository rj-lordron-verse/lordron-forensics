# Cross-Platform Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make LORDRON FORENSICS a genuinely cross-platform Python CLI application supporting Android Termux, Linux, Windows 10/11, and macOS without compromising existing Termux functionality.

**Architecture:** Isolate platform-specific detection and installation logic while ensuring core libraries use standard `pathlib.Path`, explicit UTF-8 subprocess streams, platform-aware filesystem timestamp classification, safe Windows read-only file handling, and native PowerShell (`install.ps1`) and Bash (`install.sh`) automation.

**Tech Stack:** Python 3.11+, pathlib, rich, typer, pillow, sqlite3, PowerShell, Bash, pytest.

**Spec:** User requirements for 4 target platforms (Android Termux, Linux, Windows 10/11, macOS), safe permission handling, pathlib usage, no hardcoded paths, Rich terminal safety, install.ps1 + install.sh, graceful ExifTool fallback, cross-platform unit testing with mocks, and verified platform documentation.

## Global Constraints

- Android Termux functionality must NOT be broken or degraded.
- Core application code must avoid unnecessary Termux-specific or Linux-specific assumptions.
- Pure `pathlib.Path` must be used for all filesystem paths.
- No hardcoded OS paths (like `/data/data/...`, `/sdcard/...`, `/var/log/...`).
- Safe handling of file permissions across POSIX (`0o444`) and Windows (`stat.S_IREAD`/`stat.S_IWRITE`).
- SQLite database paths and connections must be clean and safe across platforms.
- Rich terminal output must be encoding-safe across Windows cmd/PowerShell, macOS Terminal, and Linux/Termux.
- Do not push to GitHub.

## Review Focus

1. Windows drive letters and case insensitivity in path traversal checks (`safe_relative_path`).
2. Subprocess text decoding failure on Windows default ANSI code page when calling external tools.
3. Termux binary dependency preservation (Pillow via `pkg` vs pip wheel build failure).
4. `st_ctime` misinterpretation between Windows (creation time) and Linux (metadata change time).
5. Pytest cleanup failure on Windows when deleting temporary directories containing read-only (`0o444`) vault files.

---

### Task 1: Core Path & Console Encoding Safety

**Files:**
- Modify: `lordron/core/console.py`
- Modify: `lordron/core/paths.py`
- Test: `tests/test_cross_platform.py`

- [ ] Add stream reconfigure to `lordron/core/console.py` for safe UTF-8 rendering on Windows consoles without crashing if `reconfigure` is unavailable.
- [ ] Update `lordron/core/paths.py` `safe_relative_path` to handle Windows drive letters, case-insensitivity, and cross-drive paths cleanly.
- [ ] Update `validate_file_path` in `lordron/core/paths.py` to normalize path representations safely across platforms.

### Task 2: Platform-Aware Timestamps & File Intelligence

**Files:**
- Modify: `lordron/core/file_detection.py`
- Modify: `lordron/modules/timeline/engine.py`
- Test: `tests/test_cross_platform.py`

- [ ] Update `inspect_file` in `lordron/core/file_detection.py` to detect `st_birthtime` (macOS/BSD) and distinguish Windows creation time from Linux inode metadata change time.
- [ ] Update `TimelineEngine` in `lordron/modules/timeline/engine.py` to provide platform-accurate summary descriptions and reliability warnings for filesystem timestamps.

### Task 3: Graceful Optional Tool Handling & Subprocess Encoding

**Files:**
- Modify: `lordron/modules/metadata_lab/exif_reader.py`
- Test: `tests/test_cross_platform.py`

- [ ] Specify `encoding="utf-8", errors="replace"` in `subprocess.run` inside `extract_image_metadata`.
- [ ] Provide explicit, graceful feedback when `--exiftool` is requested but `exiftool` binary is not found in PATH, without raising exceptions.

### Task 4: Diagnostics & Platform Doctor

**Files:**
- Modify: `lordron/modules/diagnostics/doctor.py`
- Test: `tests/test_diagnostics.py`
- Test: `tests/test_cross_platform.py`

- [ ] Generalize platform inspection in `run_system_diagnostics` to identify Linux, macOS (Darwin), Windows, Android Termux, and WSL.
- [ ] Add platform-specific package manager remediation recommendations for missing optional tools (`winget`/`choco` on Windows, `brew` on macOS, `pkg` on Termux, `apt`/`dnf` on Linux).

### Task 5: Windows PowerShell Native Installer (`install.ps1`)

**Files:**
- Create: `install.ps1`
- Test: `tests/test_cross_platform.py`

- [ ] Author `install.ps1` with full feature parity to `install.sh`:
  - Detect Windows OS and CPU architecture.
  - Verify Python 3.11+ runtime.
  - Create `.venv` virtual environment.
  - Install dependencies and editable package `pip install -e .`.
  - Verify `lordron` command.
  - Detect optional tools (`pypdf`, `exiftool`, `pytest`, `ruff`) with Windows `winget` advice.
  - Print colored step-by-step progress and activation instructions (`.\.venv\Scripts\Activate.ps1`).

### Task 6: Cross-Platform Test Suite & Fixture Hardening

**Files:**
- Modify: `tests/test_cli_guided.py`
- Modify: `tests/conftest.py`
- Create: `tests/test_cross_platform.py`

- [ ] Guard `test_install_script_syntax` in `tests/test_cli_guided.py` so it skips when `bash` is not available.
- [ ] Add test for `install.ps1` syntax if `pwsh` or `powershell` is in PATH.
- [ ] Add fixture teardown helper in `tests/conftest.py` ensuring read-only vault files are reset to writable so Windows temp cleanup never fails.
- [ ] Write comprehensive unit tests in `tests/test_cross_platform.py` with mocks for Windows, macOS, and Linux behavior.

### Task 7: Documentation & CLI Help Alignment

**Files:**
- Modify: `README.md`
- Modify: `lordron/cli/help_system.py`

- [ ] Add dedicated installation sections for Android Termux, Linux, macOS, and Windows 10/11 (PowerShell) in `README.md`.
- [ ] Update `lordron/cli/help_system.py` with cross-platform installation and activation instructions.
- [ ] Document verified platforms (Android Termux, Linux) and awaiting live verification platforms (Windows, macOS).

### Task 8: Verification & Compatibility Audit Report Artifact

**Files:**
- Artifact: `<appDataDir>/brain/<conversation-id>/cross_platform_audit_report.md`

- [ ] Run full test suite with `pytest -v`.
- [ ] Run `ruff check lordron tests`.
- [ ] Generate the comprehensive Compatibility Audit Report artifact with verified findings, platform status matrix, and architecture improvements.
