"""
Pytest configuration and synthetic fixtures for LORDRON Forensics.
"""

import os
import pytest
from lordron.database.repository import ForensicsRepository
from lordron.modules.evidence_manager.manager import EvidenceManager


@pytest.fixture
def temp_env(tmp_path, monkeypatch):
    """Set isolated LORDRON_HOME to a temporary test directory with cross-platform teardown."""
    lordron_home = tmp_path / ".lordron_test"
    lordron_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("LORDRON_HOME", str(lordron_home))
    yield lordron_home
    # Cross-platform teardown: unlock read-only vault files so Windows/tmp_path cleanup succeeds
    if lordron_home.exists():
        for root, _, files in os.walk(lordron_home):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    os.chmod(fpath, 0o666)
                except OSError:
                    pass


@pytest.fixture
def test_repo(temp_env):
    """Provide an isolated SQLite forensics repository."""
    db_path = temp_env / "test_forensics.db"
    return ForensicsRepository(db_path=db_path)


@pytest.fixture
def evidence_mgr(test_repo):
    """Provide an EvidenceManager bound to the isolated test repository."""
    return EvidenceManager(repo=test_repo)


@pytest.fixture
def sample_text_file(tmp_path):
    """Create a synthetic text file fixture."""
    p = tmp_path / "notes.txt"
    p.write_text("Case notes: Subject visited server on port 443.\n", encoding="utf-8")
    return p


@pytest.fixture
def sample_mismatched_file(tmp_path):
    """Create a file disguised with .jpg extension but containing ELF magic bytes."""
    p = tmp_path / "disguised_payload.jpg"
    # ELF magic: \x7fELF
    p.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    return p


@pytest.fixture
def sample_log_file(tmp_path):
    """Create a synthetic authentication log file fixture."""
    p = tmp_path / "auth.log"
    content = """Mar 29 10:14:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.50 port 49200 ssh2
Mar 29 10:14:03 server sshd[1235]: Failed password for invalid user admin from 192.168.1.50 port 49202 ssh2
Mar 29 10:14:05 server sshd[1236]: Accepted password for raj from 192.168.1.10 port 49210 ssh2
Mar 29 10:15:00 server sudo: pam_authenticate failed for user guest
"""
    p.write_text(content, encoding="utf-8")
    return p
