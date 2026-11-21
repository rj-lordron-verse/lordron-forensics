"""
Tests for guided CLI features, interactive helpers, demo automation, help system, and installer.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from typer.testing import CliRunner

from lordron.cli.commands import app
from lordron.cli.dashboard import render_dashboard_footer
from lordron.cli.demo import ensure_sample_files
from lordron.cli.interactive import prompt_path
from lordron.core.console import console

runner = CliRunner()


def test_cli_version():
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "LORDRON FORENSICS" in res.stdout
    assert "Raj" in res.stdout


def test_cli_doctor_json():
    res = runner.invoke(app, ["doctor", "--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert "overall_health" in data
    assert data["brand"] == "LORDRON"


def test_cli_guide():
    res = runner.invoke(app, ["guide", "--quiet"])
    assert res.exit_code == 0
    assert "GOLDEN RULES" in res.stdout
    assert "WORKFLOW" in res.stdout
    assert "CHEAT SHEET" in res.stdout


def test_cli_subcommands_display_help_when_no_args():
    for sub in ["file", "case", "hash", "metadata", "logs", "network"]:
        res = runner.invoke(app, [sub])
        assert res.exit_code == 0
        assert "Usage: lordron" in res.stdout


def test_cli_dash_h_and_double_dash_help_on_all_commands():
    """Verify that both -h and --help work on root and subcommands."""
    commands_to_test = [
        [],
        ["file"],
        ["case"],
        ["logs"],
        ["network"],
        ["report"],
    ]

    for cmd in commands_to_test:
        res_h = runner.invoke(app, cmd + ["-h"])
        assert res_h.exit_code == 0, f"-h failed on command: {cmd}"
        assert "Usage: lordron" in res_h.stdout

        res_help = runner.invoke(app, cmd + ["--help"])
        assert res_help.exit_code == 0, f"--help failed on command: {cmd}"
        assert "Usage: lordron" in res_help.stdout


def test_cli_help_command():
    """Verify lordron help command outputs full manual, installation, and footer."""
    res = runner.invoke(app, ["help"])
    assert res.exit_code == 0
    assert "HELP & DOCUMENTATION SYSTEM" in res.stdout
    assert "ALL COMMANDS & SUBCOMMANDS REFERENCE" in res.stdout
    assert "INSTALLATION INSTRUCTIONS" in res.stdout
    assert "PRACTICAL USAGE EXAMPLES" in res.stdout
    assert "LORDRON FORENSICS | v1.0.0" in res.stdout
    assert "/help for all commands | /exit to quit" in res.stdout


def test_dashboard_footer_content():
    """Verify persistent footer contains required text."""
    with console.capture() as capture:
        render_dashboard_footer()
    output = capture.get()
    assert "LORDRON FORENSICS | v1.0.0" in output
    assert "/help for all commands | /exit to quit" in output


def test_dashboard_footer_help_rendering():
    """Regression test: /help footer renders without MarkupError and contains /help shortcut."""
    with console.capture() as capture:
        render_dashboard_footer()
    output = capture.get()
    assert "/help" in output
    assert "for all commands" in output


def test_dashboard_footer_exit_rendering():
    """Regression test: /exit footer renders without MarkupError and contains /exit shortcut."""
    with console.capture() as capture:
        render_dashboard_footer()
    output = capture.get()
    assert "LORDRON FORENSICS | v1.0.0" in output
    assert "/exit" in output
    assert "to quit" in output


def test_dashboard_rendering_without_exceptions():
    """Regression test: Full dashboard renders without MarkupError or exceptions."""
    from lordron.cli.dashboard import display_dashboard

    # Render full interactive dashboard (with banner, modules table, beginner panel, footer)
    with console.capture() as capture:
        display_dashboard(quiet=False)
    out = capture.get()
    assert "FORENSIC MODULES CATALOG" in out
    assert "LORDRON FORENSICS | v1.0.0" in out
    assert "/help" in out
    assert "/exit" in out

    # Render quiet dashboard
    with console.capture() as capture_quiet:
        display_dashboard(quiet=True)
    out_quiet = capture_quiet.get()
    assert "FORENSIC MODULES CATALOG" in out_quiet
    assert "LORDRON FORENSICS | v1.0.0" in out_quiet


def test_error_messages_containing_square_brackets(capsys):
    """Regression test: print_error never causes a second MarkupError on bracketed error strings."""
    from lordron.core.console import print_error

    bracketed_messages = [
        "Failed with [/help] shortcut tag",
        "Failed with [/exit] shortcut tag",
        "Error: [Errno 2] No such file or directory: '/tmp/test[1].raw'",
        "Integrity failure in chunk [0]: expected [a-f0-9]{64}",
        "Closing tag [/bold red] without matching open tag",
        "Unclosed tag [bold red with missing bracket",
        "Nested brackets [[]] and [1-9] command options",
    ]

    for msg in bracketed_messages:
        print_error(msg)

    captured = capsys.readouterr()
    for msg in bracketed_messages:
        assert msg in captured.err
        assert "✘ [ERROR]" in captured.err


def test_cli_json_root_callback():
    res = runner.invoke(app, ["--json"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["name"] == "lordron-forensics"
    assert data["version"] == "1.0.0"
    assert data["brand"] == "LORDRON"


def test_cli_demo_auto(temp_env, monkeypatch):
    """Test automated demo execution in isolated test environment."""
    case_test_id = "CASE-TEST-AUTO-DEMO"
    res = runner.invoke(app, ["demo", "--auto", "--quiet", "--case-id", case_test_id])
    assert res.exit_code == 0
    assert "DEMONSTRATION COMPLETE" in res.stdout
    assert case_test_id in res.stdout

    # Verify HTML report was generated
    report_file = temp_env / "cases" / case_test_id / f"report_{case_test_id}.html"
    assert report_file.exists()


def test_ensure_sample_files():
    samples = ensure_sample_files()
    assert "payload" in samples
    assert "photo" in samples
    assert "pdf" in samples
    assert "log" in samples
    for p in samples.values():
        assert p.exists()


def test_prompt_path_quote_and_whitespace_cleaning(tmp_path, monkeypatch):
    target_file = tmp_path / "test_target.txt"
    target_file.write_text("forensic data", encoding="utf-8")

    # Simulate user entering path wrapped in double quotes
    inputs = iter([f'"{target_file}"\n'])
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: next(inputs))

    resolved = prompt_path("Enter file")
    assert resolved == target_file.resolve()


def test_prompt_path_cancel(monkeypatch):
    inputs = iter(["b\n"])
    monkeypatch.setattr("rich.prompt.Prompt.ask", lambda *args, **kwargs: next(inputs))
    resolved = prompt_path("Enter file")
    assert resolved is None


def test_python_module_execution():
    cmd = [sys.executable, "-m", "lordron", "version"]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    assert proc.returncode == 0
    assert "LORDRON FORENSICS" in proc.stdout


def test_install_script_syntax():
    """Verify install.sh has valid bash syntax if bash is present."""
    install_script = Path(__file__).resolve().parent.parent / "install.sh"
    assert install_script.exists()
    import shutil
    if shutil.which("bash") is None:
        pytest.skip("bash is not available on this platform")
    proc = subprocess.run(["bash", "-n", str(install_script)], check=False, capture_output=True, text=True)
    assert proc.returncode == 0, f"install.sh syntax error: {proc.stderr}"


def test_install_powershell_script_exists_and_syntax():
    """Verify install.ps1 exists and has valid PowerShell syntax if pwsh/powershell is present."""
    install_ps1 = Path(__file__).resolve().parent.parent / "install.ps1"
    assert install_ps1.exists()
    import shutil
    ps_cmd = shutil.which("pwsh") or shutil.which("powershell")
    if not ps_cmd:
        # If no PowerShell interpreter installed, verify basic script structure
        content = install_ps1.read_text(encoding="utf-8")
        assert "LORDRON FORENSICS" in content
        assert "$venvPython" in content
        assert "Print-Banner" in content
        return

    proc = subprocess.run(
        [ps_cmd, "-NoProfile", "-Command", f"& {{ [Management.Automation.Language.Parser]::ParseFile('{install_ps1}', [ref]$null, [ref]$null) }}"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0


def test_cli_interactive_prompt_no_markup_error(capsys):
    """Ensure running lordron without arguments in interactive TTY does not raise MarkupError."""
    from unittest.mock import patch
    with patch("sys.stdin.isatty", return_value=True), patch("rich.prompt.Prompt.ask", return_value="/exit"):
        app([], standalone_mode=False)
    captured = capsys.readouterr()
    assert "Options: Enter [1-9] for module" in captured.out


def test_console_helpers_escape_markup():
    """Ensure console print helpers do not raise MarkupError on bracketed error strings."""
    from lordron.core.console import print_error, print_info, print_success, print_warning
    print_error("Failed with [/help] and [unknown_tag] and [Errno 2]")
    print_warning("Warning with [/exit] and [bold]")
    print_info("Info with [1-9] and [/something]")
    print_success("Success with [OK] and [/test]")
