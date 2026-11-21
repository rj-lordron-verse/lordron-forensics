# ==============================================================================
# LORDRON FORENSICS — Windows PowerShell Automated Installer
# "Every File Has a Story. Find It."
# Created by Raj | Brand: LORDRON
# ==============================================================================

# Stop on errors
$ErrorActionPreference = "Stop"

function Print-Banner {
    Write-Host @"
  _      ____  _____  _____  _____   ____  _   _ 
 | |    / __ \|  __ \|  __ \|  __ \ / __ \| \ | |
 | |   | |  | | |__) | |  | | |__) | |  | |  \| |
 | |   | |  | |  _  /| |  | |  _  /| |  | | . ` |
 | |___| |__| | | \ \| |__| | | \ \| |__| | |\  |
 |______\____/|_|  \_\_____/|_|  \_\\____/|_| \_|

          DIGITAL INVESTIGATION TOOLKIT
         "Every File Has a Story. Find It."
"@ -ForegroundColor Cyan

    Write-Host "LORDRON Automated Dependency & Environment Installer for Windows" -ForegroundColor White
    Write-Host "────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
}

function Write-Step([string]$msg) {
    Write-Host "`n[STEP] $msg" -ForegroundColor Cyan
}

function Write-Success([string]$msg) {
    Write-Host "  ✔ [SUCCESS] $msg" -ForegroundColor Green
}

function Write-WarnMsg([string]$msg) {
    Write-Host "  ▲ [WARNING] $msg" -ForegroundColor Yellow
}

function Write-InfoMsg([string]$msg) {
    Write-Host "  ℹ [INFO] $msg" -ForegroundColor Blue
}

function Write-ErrorMsg([string]$msg) {
    Write-Host "  ✘ [ERROR] $msg" -ForegroundColor Red
}

try {
    Print-Banner

    # --------------------------------------------------------------------------
    # 1. Environment & Architecture Detection
    # --------------------------------------------------------------------------
    Write-Step "1. Detecting Windows host operating system and CPU architecture..."
    $osVersion = [System.Environment]::OSVersion.VersionString
    $arch = $env:PROCESSOR_ARCHITECTURE
    Write-Success "Detected Platform: Windows ($osVersion) | Architecture: $arch"

    # --------------------------------------------------------------------------
    # 2. Python Version Compatibility Check (>= 3.11 required)
    # --------------------------------------------------------------------------
    Write-Step "2. Checking Python runtime compatibility (>= 3.11 required)..."

    $pythonCmd = $null
    $candidates = @("py", "python", "python3")

    foreach ($cmd in $candidates) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) {
            try {
                $checkVer = & $cmd -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" 2>$null
                if ($LASTEXITCODE -eq 0) {
                    $pythonCmd = $cmd
                    break
                }
            } catch {
                # Continue searching candidates
            }
        }
    }

    if (-not $pythonCmd) {
        Write-ErrorMsg "Compatible Python 3.11+ runtime not found in PATH!"
        Write-Host "`nRemediation for Windows:" -ForegroundColor Yellow
        Write-Host "  • Install via Windows Package Manager:" -ForegroundColor White
        Write-Host "    winget install Python.Python.3.12" -ForegroundColor Cyan
        Write-Host "  • Or download installer from: https://www.python.org/downloads/windows/" -ForegroundColor White
        Write-Host "  • IMPORTANT: Make sure to check 'Add Python to PATH' during installation.`n" -ForegroundColor Yellow
        exit 1
    }

    $pyVer = & $pythonCmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')"
    Write-Success "Found Python $pyVer using '$pythonCmd'"

    # --------------------------------------------------------------------------
    # 3. Virtual Environment Creation
    # --------------------------------------------------------------------------
    $projectDir = $PSScriptRoot
    if (-not $projectDir) {
        $projectDir = (Get-Location).Path
    }
    $venvDir = Join-Path $projectDir ".venv"

    Write-Step "3. Setting up isolated Python virtual environment at $venvDir..."

    if (-not (Test-Path $venvDir)) {
        & $pythonCmd -m venv $venvDir
    }

    $venvPython = Join-Path $venvDir "Scripts\python.exe"
    $venvPip = Join-Path $venvDir "Scripts\pip.exe"
    $venvBin = Join-Path $venvDir "Scripts"

    if (-not (Test-Path $venvPython)) {
        Write-ErrorMsg "Virtual environment creation failed: $venvPython is missing."
        exit 1
    }
    Write-Success "Virtual environment initialized successfully."

    # --------------------------------------------------------------------------
    # 4. Dependency Installation
    # --------------------------------------------------------------------------
    Write-Step "4. Installing core dependencies (typer, rich, pillow)..."

    $depsSatisfied = $false
    try {
        & $venvPython -c "import typer, rich, PIL" 2>$null
        if ($LASTEXITCODE -eq 0) {
            $depsSatisfied = $true
        }
    } catch {
        $depsSatisfied = $false
    }

    if ($depsSatisfied) {
        Write-Success "Required dependencies (typer, rich, pillow) already satisfied."
    } else {
        Write-InfoMsg "Installing required dependencies via pip..."
        $reqFile = Join-Path $projectDir "requirements.txt"
        if (Test-Path $reqFile) {
            & $venvPip install --default-timeout=15 -r $reqFile
        } else {
            & $venvPip install --default-timeout=15 "typer>=0.9.0,<0.12.0" "click>=8.0.0,<8.2.0" "rich>=13.0.0" "pillow>=10.0.0"
        }
        Write-Success "Dependencies installed in virtual environment."
    }

    # --------------------------------------------------------------------------
    # 5. Install LORDRON Package in Editable Mode
    # --------------------------------------------------------------------------
    Write-Step "5. Installing LORDRON Forensics in editable mode (-e .)..."
    & $venvPip install -e $projectDir --no-deps
    Write-Success "LORDRON package installed in editable development mode."

    # --------------------------------------------------------------------------
    # 6. Verify CLI Execution
    # --------------------------------------------------------------------------
    Write-Step "6. Verifying CLI command execution..."
    $verifyOut = & $venvPython -m lordron version 2>&1
    if ($verifyOut -match "LORDRON FORENSICS") {
        Write-Success "Verification passed: $verifyOut"
    } else {
        Write-ErrorMsg "Verification failed! Output: $verifyOut"
        exit 1
    }

    $lordronExe = Join-Path $venvBin "lordron.exe"
    if (Test-Path $lordronExe) {
        Write-Success "Executable entry point $lordronExe is operational."
    }

    # --------------------------------------------------------------------------
    # 7. Detect Optional Forensic Dependencies
    # --------------------------------------------------------------------------
    Write-Step "7. Inspecting optional forensic dependencies..."

    # A) pypdf
    try {
        & $venvPython -c "import pypdf" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "pypdf: Installed (Full PDF structure parser enabled)"
        } else {
            Write-WarnMsg "pypdf: Not installed (Native binary fallback parser active)"
            Write-Host "       To install: & `"$venvPip`" install pypdf" -ForegroundColor DarkGray
        }
    } catch {
        Write-WarnMsg "pypdf: Not installed (Native binary fallback parser active)"
    }

    # B) exiftool
    $hasExiftool = Get-Command exiftool -ErrorAction SilentlyContinue
    if ($hasExiftool) {
        Write-Success "exiftool: Detected at $($hasExiftool.Source)"
    } else {
        Write-WarnMsg "exiftool: Not found in PATH"
        Write-Host "       To install via winget: winget install OliverBetz.ExifTool" -ForegroundColor DarkGray
        Write-Host "       Or via Chocolatey:     choco install exiftool" -ForegroundColor DarkGray
    }

    # C) pytest
    try {
        & $venvPython -c "import pytest" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "pytest: Installed (Test runner ready)"
        } else {
            Write-InfoMsg "pytest: Not installed in venv"
            Write-Host "       To install: & `"$venvPip`" install pytest" -ForegroundColor DarkGray
        }
    } catch {
        Write-InfoMsg "pytest: Not installed in venv"
    }

    # D) ruff
    $hasRuff = Get-Command ruff -ErrorAction SilentlyContinue
    if ($hasRuff) {
        Write-Success "ruff: Detected (Linting tool available)"
    } else {
        Write-InfoMsg "ruff: Not found"
        Write-Host "       To install: & `"$venvPip`" install ruff" -ForegroundColor DarkGray
    }

    # --------------------------------------------------------------------------
    # 8. Installation Summary & Instructions
    # --------------------------------------------------------------------------
    Write-Host "`n════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  ✔ LORDRON FORENSICS INSTALLATION COMPLETE!" -ForegroundColor Green
    Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

    Write-Host "`nINSTALLATION SUMMARY:" -ForegroundColor White
    Write-Host "  • Platform:         Windows ($osVersion)" -ForegroundColor Yellow
    Write-Host "  • Python Version:   $pyVer" -ForegroundColor Yellow
    Write-Host "  • Virtual Env:      $venvDir" -ForegroundColor Cyan
    Write-Host "  • CLI Binary:       $lordronExe" -ForegroundColor Green
    Write-Host "  • Status:           READY FOR INVESTIGATION" -ForegroundColor Green

    Write-Host "`nHOW TO ACTIVATE & RUN IN POWERSHELL:" -ForegroundColor White
    Write-Host "  1. If script execution is restricted, allow current session:" -ForegroundColor DarkGray
    Write-Host "     Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" -ForegroundColor Cyan
    Write-Host "  2. Activate virtual environment:" -ForegroundColor DarkGray
    Write-Host "     .\.venv\Scripts\Activate.ps1" -ForegroundColor Cyan
    Write-Host "  3. Launch interactive investigation lab:" -ForegroundColor DarkGray
    Write-Host "     lordron             # Main dashboard with persistent footer" -ForegroundColor Green
    Write-Host "     lordron demo        # Guided walkthrough of simulated incident" -ForegroundColor Green
    Write-Host "     lordron guide       # 5 Golden Rules & CLI cheatsheet" -ForegroundColor Green
    Write-Host "     lordron doctor      # System readiness diagnostics" -ForegroundColor Green
    Write-Host "     lordron --help      # Complete options reference" -ForegroundColor Green

    Write-Host "`nCreated by Raj | Brand: LORDRON Forensics`n" -ForegroundColor DarkGray

} catch {
    Write-Host "`n════════════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-ErrorMsg "Installation failed: $($_.Exception.Message)"
    Write-Host "TROUBLESHOOTING INSTRUCTIONS:" -ForegroundColor Yellow
    Write-Host "  • Verify Python 3.11+ is installed and 'python' is accessible in PATH." -ForegroundColor White
    Write-Host "  • If execution policy blocks scripts, run in PowerShell:" -ForegroundColor White
    Write-Host "    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass" -ForegroundColor Cyan
    Write-Host "════════════════════════════════════════════════════════════════`n" -ForegroundColor Red
    exit 1
}
