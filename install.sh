#!/usr/bin/env bash
# ==============================================================================
# LORDRON FORENSICS — Official Automated Installer
# "Every File Has a Story. Find It."
# Created by Raj | Brand: LORDRON
# ==============================================================================

set -e

# ANSI Color Codes
COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_DIM="\033[2m"
COLOR_RED="\033[31m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_BLUE="\033[34m"
COLOR_MAGENTA="\033[35m"
COLOR_CYAN="\033[36m"
COLOR_WHITE="\033[37m"

print_header() {
    echo -e "${COLOR_CYAN}${COLOR_BOLD}"
    cat << "EOF"
  _      ____  _____  _____  _____   ____  _   _ 
 | |    / __ \|  __ \|  __ \|  __ \ / __ \| \ | |
 | |   | |  | | |__) | |  | | |__) | |  | |  \| |
 | |   | |  | |  _  /| |  | |  _  /| |  | | . ` |
 | |___| |__| | | \ \| |__| | | \ \| |__| | |\  |
 |______\____/|_|  \_\_____/|_|  \_\\____/|_| \_|

          DIGITAL INVESTIGATION TOOLKIT
         "Every File Has a Story. Find It."
EOF
    echo -e "${COLOR_RESET}"
    echo -e "${COLOR_WHITE}${COLOR_BOLD}LORDRON Automated Dependency & Environment Installer${COLOR_RESET}"
    echo -e "${COLOR_DIM}────────────────────────────────────────────────────────────────${COLOR_RESET}"
}

print_step() {
    echo -e "\n${COLOR_CYAN}${COLOR_BOLD}[STEP]${COLOR_RESET} ${COLOR_WHITE}${1}${COLOR_RESET}"
}

print_success() {
    echo -e "${COLOR_GREEN}${COLOR_BOLD}  ✔ [SUCCESS]${COLOR_RESET} ${1}"
}

print_warn() {
    echo -e "${COLOR_YELLOW}${COLOR_BOLD}  ▲ [WARNING]${COLOR_RESET} ${1}"
}

print_info() {
    echo -e "${COLOR_BLUE}${COLOR_BOLD}  ℹ [INFO]${COLOR_RESET} ${1}"
}

print_error() {
    echo -e "${COLOR_RED}${COLOR_BOLD}  ✘ [ERROR]${COLOR_RESET} ${1}" >&2
}

# Error handler trap
trap_error() {
    local exit_code=$?
    echo -e "\n${COLOR_RED}${COLOR_BOLD}════════════════════════════════════════════════════════════════${COLOR_RESET}"
    print_error "Installation failed at line $1 with exit code $exit_code."
    echo -e "${COLOR_YELLOW}${COLOR_BOLD}TROUBLESHOOTING INSTRUCTIONS:${COLOR_RESET}"
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo -e "  • ${COLOR_WHITE}Termux detected:${COLOR_RESET} Ensure Termux packages are up to date:"
        echo -e "    ${COLOR_CYAN}pkg update && pkg install -y python python-pillow exiftool ruff${COLOR_RESET}"
        echo -e "  • Avoid compiling Pillow from pip wheel source in Termux without C compiler."
    else
        echo -e "  • ${COLOR_WHITE}Debian/Ubuntu:${COLOR_RESET} sudo apt update && sudo apt install -y python3-venv python3-pip"
        echo -e "  • ${COLOR_WHITE}Fedora/RHEL:${COLOR_RESET}   sudo dnf install -y python3-pip python3-devel"
        echo -e "  • ${COLOR_WHITE}macOS:${COLOR_RESET}         brew install python@3.12"
    fi
    echo -e "  • Ensure Python 3.11+ is installed and accessible in PATH."
    echo -e "${COLOR_RED}${COLOR_BOLD}════════════════════════════════════════════════════════════════${COLOR_RESET}\n"
    exit "$exit_code"
}

trap 'trap_error $LINENO' ERR

# ------------------------------------------------------------------------------
# 1. Environment & Architecture Detection
# ------------------------------------------------------------------------------
print_header

print_step "1. Detecting host operating system and CPU architecture..."
OS="$(uname -s)"
ARCH="$(uname -m)"

IS_TERMUX=0
if [ -n "$TERMUX_VERSION" ] || [[ "${PREFIX:-}" == *"com.termux"* ]] || [[ "${HOME:-}" == *"com.termux"* ]]; then
    IS_TERMUX=1
fi

if [ "$IS_TERMUX" -eq 1 ]; then
    ENV_TYPE="Android Termux"
elif [ "$OS" = "Linux" ]; then
    ENV_TYPE="Linux Desktop / Server"
elif [ "$OS" = "Darwin" ]; then
    ENV_TYPE="macOS (${ARCH})"
elif [[ "$OS" == *"MINGW"* ]] || [[ "$OS" == *"MSYS"* ]] || [[ "$OS" == *"CYGWIN"* ]]; then
    ENV_TYPE="Windows Subsystem / MinGW"
else
    ENV_TYPE="Generic UNIX (${OS})"
fi

print_success "Detected Platform: ${ENV_TYPE} | Architecture: ${ARCH}"

# ------------------------------------------------------------------------------
# 2. Python Version Compatibility Check
# ------------------------------------------------------------------------------
print_step "2. Checking Python runtime compatibility (>= 3.11 required)..."

PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        if "$cmd" -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >/dev/null 2>&1; then
            PYTHON_CMD="$(command -v "$cmd")"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    print_error "Compatible Python 3.11+ runtime not found in PATH!"
    echo -e "\n${COLOR_YELLOW}Remediation:${COLOR_RESET}"
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo -e "  Run: ${COLOR_CYAN}pkg update && pkg install -y python${COLOR_RESET}"
    elif [ "$OS" = "Darwin" ]; then
        echo -e "  Run: ${COLOR_CYAN}brew install python@3.12${COLOR_RESET}"
    else
        echo -e "  Run: ${COLOR_CYAN}sudo apt install python3 python3-venv python3-pip${COLOR_RESET}"
    fi
    exit 1
fi

PY_VER="$("$PYTHON_CMD" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")"
print_success "Found Python ${PY_VER} at ${PYTHON_CMD}"

# ------------------------------------------------------------------------------
# 3. Virtual Environment Creation
# ------------------------------------------------------------------------------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"

print_step "3. Setting up isolated Python virtual environment at ${VENV_DIR}..."

if [ "$IS_TERMUX" -eq 1 ]; then
    # In Termux, --system-site-packages ensures Termux-provided binary packages
    # (like python-pillow compiled for Android/Bionic) are accessible in .venv.
    print_info "Termux mode: Creating virtual environment with --system-site-packages..."
    "$PYTHON_CMD" -m venv --system-site-packages "$VENV_DIR"
else
    "$PYTHON_CMD" -m venv "$VENV_DIR"
fi

VENV_PYTHON="${VENV_DIR}/bin/python"
VENV_PIP="${VENV_DIR}/bin/pip"
VENV_BIN="${VENV_DIR}/bin"

if [ ! -f "$VENV_PYTHON" ]; then
    print_error "Virtual environment creation failed: $VENV_PYTHON missing."
    exit 1
fi

print_success "Virtual environment initialized successfully."

# ------------------------------------------------------------------------------
# 4. Dependency Installation (pyproject.toml as single source of truth)
# ------------------------------------------------------------------------------
print_step "4. Installing core dependencies (typer, rich, pillow)..."

# Ensure Termux binary packages if available to avoid compiling from source
if [ "$IS_TERMUX" -eq 1 ]; then
    if command -v pkg >/dev/null 2>&1; then
        if ! "$VENV_PYTHON" -c "import PIL" >/dev/null 2>&1; then
            print_info "Installing python-pillow via Termux package manager..."
            pkg install -y python-pillow >/dev/null 2>&1 || true
        fi
    fi
fi

# Check if dependencies are already satisfied in virtual environment
if "$VENV_PYTHON" -c "import typer, rich, PIL" >/dev/null 2>&1; then
    print_success "Required dependencies (typer, rich, pillow) already satisfied."
else
    print_info "Installing required dependencies via pip..."
    if [ -f "${PROJECT_DIR}/requirements.txt" ]; then
        "$VENV_PIP" install --default-timeout=15 -r "${PROJECT_DIR}/requirements.txt"
    else
        "$VENV_PIP" install --default-timeout=15 "typer>=0.9.0,<0.12.0" "click>=8.0.0,<8.2.0" "rich>=13.0.0" "pillow>=10.0.0"
    fi
    print_success "Dependencies installed in virtual environment."
fi

# ------------------------------------------------------------------------------
# 5. Install LORDRON Package in Editable Mode
# ------------------------------------------------------------------------------
print_step "5. Installing LORDRON Forensics in editable mode (-e .)..."

"$VENV_PIP" install -e "$PROJECT_DIR" --no-deps

print_success "LORDRON package installed in editable development mode."

# ------------------------------------------------------------------------------
# 6. Verify CLI Execution
# ------------------------------------------------------------------------------
print_step "6. Verifying CLI command execution..."

VERIFY_OUT="$("$VENV_PYTHON" -m lordron version)"
if [[ "$VERIFY_OUT" == *"LORDRON FORENSICS"* ]]; then
    print_success "Verification passed: ${VERIFY_OUT}"
else
    print_error "Verification failed! Output: ${VERIFY_OUT}"
    exit 1
fi

# Also verify that the binary in .venv/bin/lordron works
if [ -x "${VENV_BIN}/lordron" ]; then
    "${VENV_BIN}/lordron" version >/dev/null 2>&1
    print_success "Executable entry point ${VENV_BIN}/lordron is operational."
fi

# ------------------------------------------------------------------------------
# 7. Detect Optional Dependencies
# ------------------------------------------------------------------------------
print_step "7. Inspecting optional forensic dependencies..."

# A) pypdf (Deep PDF metadata parsing)
HAVE_PYPDF=0
if "$VENV_PYTHON" -c "import pypdf" >/dev/null 2>&1; then
    HAVE_PYPDF=1
    print_success "pypdf: Installed (Full PDF structure parser enabled)"
else
    print_warn "pypdf: Not installed (Native binary fallback parser active)"
    echo -e "       ${COLOR_DIM}To install: ${VENV_PIP} install pypdf${COLOR_RESET}"
fi

# B) exiftool (External image metadata extraction)
HAVE_EXIFTOOL=0
if command -v exiftool >/dev/null 2>&1; then
    HAVE_EXIFTOOL=1
    print_success "exiftool: Detected at $(command -v exiftool)"
else
    print_warn "exiftool: Not found in PATH"
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo -e "       ${COLOR_DIM}To install in Termux: pkg install -y exiftool${COLOR_RESET}"
    elif [ "$OS" = "Darwin" ]; then
        echo -e "       ${COLOR_DIM}To install on macOS: brew install exiftool${COLOR_RESET}"
    else
        echo -e "       ${COLOR_DIM}To install on Debian/Ubuntu: sudo apt install -y libimage-exiftool-perl${COLOR_RESET}"
    fi
fi

# C) pytest (Developer test suite)
HAVE_PYTEST=0
if "$VENV_PYTHON" -c "import pytest" >/dev/null 2>&1; then
    HAVE_PYTEST=1
    print_success "pytest: Installed (Test runner ready)"
else
    print_info "pytest: Not installed in venv"
    echo -e "       ${COLOR_DIM}To install: ${VENV_PIP} install pytest${COLOR_RESET}"
fi

# D) ruff (Linter & code formatter)
HAVE_RUFF=0
if command -v ruff >/dev/null 2>&1 || "$VENV_PYTHON" -c "import ruff" >/dev/null 2>&1; then
    HAVE_RUFF=1
    print_success "ruff: Detected (Linting tool available)"
else
    print_info "ruff: Not found"
    if [ "$IS_TERMUX" -eq 1 ]; then
        echo -e "       ${COLOR_DIM}To install in Termux: pkg install -y ruff (avoids compiling rust)${COLOR_RESET}"
    else
        echo -e "       ${COLOR_DIM}To install: ${VENV_PIP} install ruff${COLOR_RESET}"
    fi
fi

# ------------------------------------------------------------------------------
# 8. Installation Summary & Instructions
# ------------------------------------------------------------------------------
echo -e "\n${COLOR_CYAN}${COLOR_BOLD}════════════════════════════════════════════════════════════════${COLOR_RESET}"
echo -e "${COLOR_GREEN}${COLOR_BOLD}  ✔ LORDRON FORENSICS INSTALLATION COMPLETE!${COLOR_RESET}"
echo -e "${COLOR_CYAN}${COLOR_BOLD}════════════════════════════════════════════════════════════════${COLOR_RESET}"

echo -e "\n${COLOR_WHITE}${COLOR_BOLD}INSTALLATION SUMMARY:${COLOR_RESET}"
echo -e "  • Environment:      ${COLOR_YELLOW}${ENV_TYPE}${COLOR_RESET}"
echo -e "  • Python Version:   ${COLOR_YELLOW}${PY_VER}${COLOR_RESET}"
echo -e "  • Virtual Env:      ${COLOR_CYAN}${VENV_DIR}${COLOR_RESET}"
echo -e "  • CLI Binary:       ${COLOR_GREEN}${VENV_BIN}/lordron${COLOR_RESET}"
echo -e "  • Status:           ${COLOR_GREEN}READY FOR INVESTIGATION${COLOR_RESET}"

echo -e "\n${COLOR_WHITE}${COLOR_BOLD}HOW TO ACTIVATE & RUN:${COLOR_RESET}"
echo -e "  1. Activate virtual environment:"
echo -e "     ${COLOR_CYAN}source .venv/bin/activate${COLOR_RESET}"
echo -e ""
echo -e "  2. Launch interactive investigation lab:"
echo -e "     ${COLOR_GREEN}lordron${COLOR_RESET}           ${COLOR_DIM}# Main dashboard with persistent footer${COLOR_RESET}"
echo -e "     ${COLOR_GREEN}lordron demo${COLOR_RESET}      ${COLOR_DIM}# Guided walkthrough of simulated incident${COLOR_RESET}"
echo -e "     ${COLOR_GREEN}lordron guide${COLOR_RESET}     ${COLOR_DIM}# 5 Golden Rules & CLI cheatsheet${COLOR_RESET}"
echo -e "     ${COLOR_GREEN}lordron doctor${COLOR_RESET}    ${COLOR_DIM}# System readiness diagnostics${COLOR_RESET}"
echo -e "     ${COLOR_GREEN}lordron --help${COLOR_RESET}    ${COLOR_DIM}# Complete options reference${COLOR_RESET}"

echo -e "\n${COLOR_DIM}Created by Raj | Brand: LORDRON Forensics${COLOR_RESET}\n"
