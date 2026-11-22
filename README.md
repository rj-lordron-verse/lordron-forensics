# LORDRON FORENSICS

> **"Every File Has a Story. Find It."**

[![CI Test Suite](https://github.com/USERNAME/lordron-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/USERNAME/lordron-forensics/actions)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20Termux-brightgreen.svg)]()

**LORDRON FORENSICS** is an offline-first, cross-platform digital investigation toolkit. Designed for security analysts, incident responders, forensic students, system administrators, and investigators, LORDRON enables empirical forensic analysis directly from the terminal without mandatory cloud services, API tokens, user tracking, or external telemetry.

---

## 1. What LORDRON FORENSICS Does

LORDRON provides 9 modular digital forensics capabilities:

1. **File Intelligence (Module 01):** Inspects raw magic byte signatures (60+ file formats), determines true MIME types independent of extensions, alerts when executables or scripts are disguised as media, and detects duplicate files across entire directory trees.
2. **Metadata Lab (Module 02):** Extracts embedded EXIF metadata from images (camera model, lens, exposure, timestamps), decodes GPS coordinates to decimal degrees with OpenStreetMap links, and parses PDF document structures (title, author, subject, creator).
3. **Hash Intelligence (Module 03):** Computes chunk-buffered cryptographic digests (SHA-256, SHA-512, SHA-1, and legacy MD5) without modifying files, and verifies artifact authenticity against expected digests with auto-algorithm detection.
4. **Evidence Custody & Case Manager (Module 04):** Maintains an ACID-compliant local SQLite ledger of cases and evidence, isolates working copies in a read-only vault (`0o444`), records UTC acquisition timestamps, and maintains an immutable chain-of-custody audit log.
5. **Log Analyzer (Module 05):** Parses multi-format text logs (Syslog RFC 3164/5424, Auth.log, Apache/Nginx web logs), automatically extracts timestamps, classifies severity, identifies anomaly patterns (brute-force failures, sudo privilege escalation), and exports to CSV.
6. **Timeline Engine (Module 06):** Reconstructs unified chronological event streams by fusing filesystem timestamps, evidence acquisition baselines, and investigator notes, explicitly flagging easily altered filesystem timestamps.
7. **Passive Network Intelligence (Module 07):** Strictly passive reconnaissance: performs DNS lookups (A, AAAA, PTR), remote TLS handshake inspection, and HTTP security header analysis without aggressive port scanning.
8. **Report Generator (Module 08):** Compiles standalone, self-contained HTML forensic reports with interactive dark-mode styling, machine-readable JSON dossiers, and tabular CSV files.
9. **System Diagnostics (Module 09):** `lordron doctor` audits runtime compatibility, disk storage, database health, and core/optional dependencies.

---

## 2. Supported Platforms & Verification Status

LORDRON FORENSICS supports four primary target environments:

| Operating System / Environment | Architecture | Python Version | Verification Status |
| :--- | :--- | :--- | :--- |
| **Android Termux** | `aarch64`, `arm` | Python 3.11 – 3.14 | **VERIFIED & TESTED LIVE** (Native pkg support) |
| **Linux (Ubuntu, Debian, Fedora, Arch)** | `x86_64`, `aarch64` | Python 3.11 – 3.14 | **VERIFIED & TESTED LIVE** (Standard glibc) |
| **Windows 10 / 11 (PowerShell 5.1+, pwsh 7+)** | `x86_64`, `ARM64` | Python 3.11 – 3.13 | **TEST-VERIFIED VIA MOCKS** *(Awaiting Native Bare-Metal Windows Run)* |
| **macOS (Apple Silicon & Intel)** | `arm64`, `x86_64` | Python 3.11 – 3.14 | **TEST-VERIFIED VIA MOCKS** *(Awaiting Native Bare-Metal macOS Run)* |

> [!NOTE]
> In accordance with empirical forensic engineering standards, LORDRON FORENSICS clearly distinguishes environments tested directly on physical hosts (Android Termux, Linux) from platforms verified via synthetic cross-platform test suites awaiting bare-metal hardware validation.

---

## 3. Installation

### Option A: Linux & macOS Automated Installer (`install.sh`)

Clone the repository and run the automated bash installer:

```bash
git clone https://github.com/rj-lordron-verse/lordron-forensics.git
cd lordron-forensics
chmod +x install.sh
./install.sh
source .venv/bin/activate
```

---

### Option B: Windows 10/11 PowerShell Automated Installer (`install.ps1`)

Open PowerShell (Run as Administrator or standard user) and execute:

```powershell
git clone https://github.com/rj-lordron-verse/lordron-forensics.git
cd lordron-forensics

# If PowerShell script execution is restricted for the current session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Run the official automated Windows installer:
.\install.ps1

# Activate the virtual environment:
.\.venv\Scripts\Activate.ps1
```

The `install.ps1` script automatically:
1. Detects Windows OS build and CPU architecture (`x86_64` or `ARM64`).
2. Validates Python $\ge 3.11$ runtime (`py -3`, `python`, `python3`).
3. Creates an isolated `.venv` virtual environment.
4. Installs core dependencies (`typer`, `rich`, `pillow`).
5. Installs LORDRON in editable mode (`pip install -e .`).
6. Verifies CLI binary operation (`lordron.exe`).
7. Checks optional dependencies (`pypdf`, `exiftool`) with Windows `winget` installation tips.

---

### Option C: Android Termux Installation Details

Termux on Android uses Android's Bionic libc rather than GNU glibc. To prevent pip from attempting to compile C/Rust packages from source:

```bash
# 1. Update Termux repositories and install prebuilt binary packages:
pkg update && pkg install -y python python-pillow exiftool ruff

# 2. Clone and run the installer:
git clone https://github.com/rj-lordron-verse/lordron-forensics.git
cd lordron-forensics
chmod +x install.sh
./install.sh

# 3. Activate the virtual environment:
source .venv/bin/activate
```

---

### Option D: Manual Installation (All Platforms)

If you prefer standard manual virtual environment management:

```bash
git clone https://github.com/rj-lordron-verse/lordron-forensics.git
cd lordron-forensics

# 1. Create virtual environment
python3 -m venv .venv              # On Windows: python -m venv .venv

# 2. Activate virtual environment
source .venv/bin/activate          # On Windows: .\.venv\Scripts\Activate.ps1

# 3. Install in editable mode
pip install -e .

# 4. Verify installation
lordron doctor
```

---

## 4. First Investigation Walkthrough

### Option A: The Guided Automated Demonstration (`lordron demo`)

Every installation includes bundled synthetic forensic evidence ([sample_case](examples/sample_case)). Run the guided demo for an immediate hands-on walkthrough:

```bash
# Interactive guided tour with phase explanations:
lordron demo

# Fast automated run:
lordron demo --auto
```

### Option B: Step-by-Step Manual Triage

```bash
# 1. Triage a suspect file for disguised extensions:
lordron file inspect examples/sample_case/payload_disguised.jpg
# Result: Detects that the file is an ELF binary masquerading as a JPEG!

# 2. Extract embedded document metadata:
lordron metadata inspect examples/sample_case/document.pdf

# 3. Calculate cryptographic SHA-256 fingerprint:
lordron hash calc examples/sample_case/payload_disguised.jpg

# 4. Initialize an investigation case in the SQLite custody ledger:
lordron case create CASE-2026-001 --title "Web Server Triage" --investigator "Raj"

# 5. Acquire evidence into the read-only vault (preserves original):
lordron case add CASE-2026-001 examples/sample_case/payload_disguised.jpg --notes "Suspect upload"

# 6. Audit vault integrity against acquisition baseline:
lordron case verify CASE-2026-001

# 7. Analyze authentication logs for brute-force attacks:
lordron logs analyze examples/sample_case/auth.log

# 8. Reconstruct multi-source chronological timeline:
lordron timeline CASE-2026-001

# 9. Generate a standalone HTML report:
lordron report CASE-2026-001 --format html --output investigation_report.html
```

---

## 5. All CLI Commands & Options

Both `--help` and `-h` are supported across all commands and subcommands.

```bash
lordron --help
lordron -h
```

### Main Command Reference

| Command | Subcommands | Purpose & Example |
| :--- | :--- | :--- |
| `lordron` | *(root)* | Launches interactive dashboard with persistent terminal footer. |
| `lordron interactive` | *(root)* | Guided interactive menu environment (`lordron menu`, `lordron wizard`). |
| `lordron demo` | *(root)* | Executes simulated investigation tour (`lordron demo --auto`). |
| `lordron guide` | *(root)* | Displays 5 Golden Rules of Forensics and cheatsheet (`lordron cheat`). |
| `lordron help` | *(root)* | Displays full interactive help system, commands, and installation guide. |
| `lordron doctor` | *(root)* | Audits environment, runtime, dependencies, and database health. |
| `lordron version` | *(root)* | Shows version and brand identity (`lordron -v`). |
| `lordron file` | `inspect`, `batch`, `compare` | True signature triage, extension mismatch alerts, duplicate finding. |
| `lordron metadata`| `inspect`, `compare` | Extracts image EXIF/GPS and PDF properties. |
| `lordron hash` | `calc`, `verify`, `batch` | Multi-algorithm streaming hashes (SHA256/512/SHA1/MD5). |
| `lordron case` | `create`, `list`, `show`, `add`, `verify`, `note` | Case custody, read-only vaults (`0o444`), chain of custody audits. |
| `lordron logs` | `analyze` | Parses logs, detects anomalies, classifies severity, exports CSV. |
| `lordron timeline`| *(root)* | Chronological event fusion with source reliability warnings. |
| `lordron network` | `inspect`, `dns`, `tls` | Passive DNS lookup, TLS certificate inspection, HTTP headers. |
| `lordron report` | *(root)* | Generates standalone HTML, JSON, or CSV reports. |

### Subcommand Examples

```bash
# File Intelligence
lordron file inspect <path>
lordron file batch <dir> --recursive
lordron file compare <file1> <file2>

# Metadata Lab
lordron metadata inspect <file> [--exiftool]
lordron metadata compare <file1> <file2>

# Hash Intelligence
lordron hash <file>                       # Direct hash shortcut
lordron hash calc <file>
lordron hash verify <file> <expected_hex>
lordron hash batch <dir>

# Case & Evidence Custody
lordron case create <case_id> -t "Title" -i "Investigator"
lordron case list
lordron case show <case_id>
lordron case add <case_id> <path> -n "Acquisition notes"
lordron case verify <case_id>
lordron case note <case_id> "Investigator observation"

# Logs & Timelines
lordron logs analyze /var/log/auth.log --min-severity WARNING --csv parsed.csv
lordron timeline <case_id>

# Passive Network Intelligence
lordron network inspect example.com
lordron network dns example.com
lordron network tls example.com -p 443

# Reporting
lordron report <case_id> --format html --output report.html
lordron report <case_id> --format json
lordron report <case_id> --format csv
```

### Persistent Dashboard Footer & Interactive Commands

When running the interactive dashboard or interactive mode, a persistent footer is displayed:

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ LORDRON FORENSICS | v1.0.0                                                   │
│ /help for all commands | /exit to quit                                       │
╰──────────────────────────────────────────────────────────────────────────────╯
```

At any interactive prompt:
- Type `/help` (or `help`) to display the full command reference, subcommands, and usage guide.
- Type `/exit` (or `exit`, `quit`, `q`) to return to the shell.

---

## 6. Optional Dependencies

LORDRON works out of the box with zero optional dependencies. You can install optional tools for enhanced capabilities:

| Dependency | Category | How to Install | Capability Provided |
| :--- | :--- | :--- | :--- |
| `pypdf` | Python Package | `pip install pypdf` | Deep object-stream PDF structural parsing. |
| `exiftool` | System Binary | Termux: `pkg install exiftool`<br>Debian/Ubuntu: `sudo apt install libimage-exiftool-perl`<br>macOS: `brew install exiftool` | Extraction of rare camera tags and proprietary maker notes. |
| `pytest` | Dev Package | `pip install pytest` | Running the automated test suite. |
| `ruff` | Dev Tool | Termux: `pkg install ruff`<br>Linux/macOS: `pip install ruff` | Fast linting and code formatting. |

---

## 7. Installation Troubleshooting

### Issue 1: `python3: command not found` or Version < 3.11
- **Cause:** Python is either not installed or is an older version.
- **Fix:**
  - **Android Termux:** `pkg update && pkg install -y python`
  - **Ubuntu / Debian:** `sudo apt update && sudo apt install -y python3 python3-venv python3-pip`
  - **macOS:** `brew install python@3.12`

### Issue 2: `Error: No module named venv` on Ubuntu/Debian
- **Cause:** Debian and Ubuntu package the virtual environment module separately.
- **Fix:** `sudo apt install -y python3-venv`

### Issue 3: Pillow fails to compile from source in Termux
- **Cause:** Android Termux does not have standard GNU C compilers or glibc headers by default. Pip wheels that require C compilation will fail unless libraries are present.
- **Fix:** Do not compile Pillow from pip in Termux. Install the prebuilt Termux package:
  ```bash
  pkg install -y python-pillow
  ```
  The LORDRON `install.sh` script automatically detects Termux and creates virtual environments with `--system-site-packages` so prebuilt Termux libraries are used directly.

### Issue 4: `lordron: command not found` after opening a new shell
- **Cause:** Virtual environment has not been activated in the current shell session.
- **Fix:**
  ```bash
  cd /path/to/lordron-forensics
  source .venv/bin/activate
  ```
  Or run directly via python:
  ```bash
  python3 -m lordron
  ```

---

## 8. Uninstallation Instructions

To remove LORDRON Forensics from your system:

### 1. Remove the Virtual Environment
```bash
deactivate 2>/dev/null || true
rm -rf /path/to/lordron-forensics/.venv
```

### 2. Remove Local Cases & Evidence Database (Optional)
By default, cases, evidence vaults, and SQLite databases are stored in `~/.lordron/`. To delete all local case data:
```bash
rm -rf ~/.lordron
```

### 3. Remove the Cloned Repository
```bash
rm -rf /path/to/lordron-forensics
```

---

## 9. Security, Privacy & Integrity Limitations

1. **Offline-First Privacy Guarantee:** LORDRON Forensics performs all file triage, metadata extraction, cryptographic hashing, log analysis, and reporting **100% locally on your machine**. It transmits zero telemetry, zero error logs, and zero evidence artifacts over the network.
2. **Read-Only Preservation (`0o444`):** When evidence is acquired via `lordron case add`, the original file is never modified. A working copy is preserved in the vault and set to read-only permissions (`0o444`).
3. **Database Audit Trails:** Local SQLite audit logs record case actions and UTC timestamps. While protected against accidental tampering, local SQLite databases do not constitute write-once-read-many (WORM) hardware or distributed ledger guarantees against an adversary with root access to the host machine.
4. **Filesystem Timestamps vs. Empirical Facts:** Filesystem timestamps (`mtime`, `ctime`, `atime`) can be altered using anti-forensics tools (timestomping). LORDRON highlights these discrepancies in the timeline engine and advises investigators to cross-reference them against acquisition hashes and immutable event logs.

---

## Running the Automated Test Suite

```bash
cd lordron-forensics
pytest -v
```

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

**Created by Raj** | Brand: **LORDRON FORENSICS**
