"""
Unit tests for cryptographic hashing engine and integrity verification.
"""

import hashlib
import pytest
from lordron.core.hashing import calculate_hashes, verify_hash
from lordron.core.exceptions import FileAccessError
from lordron.modules.hash_intelligence.hasher import hash_directory_batch


def test_calculate_hashes_accuracy(tmp_path):
    f = tmp_path / "test.bin"
    test_data = b"Forensic Investigation Sample 2026"
    f.write_bytes(test_data)

    digests = calculate_hashes(f)
    assert digests["sha256"] == hashlib.sha256(test_data).hexdigest()
    assert digests["sha512"] == hashlib.sha512(test_data).hexdigest()
    assert digests["sha1"] == hashlib.sha1(test_data).hexdigest()
    assert digests["md5"] == hashlib.md5(test_data).hexdigest()


def test_streaming_large_file(tmp_path):
    f = tmp_path / "large.bin"
    # Write 2.5 MB of repeating pattern
    chunk = b"A" * (1024 * 512)
    with open(f, "wb") as out:
        for _ in range(5):
            out.write(chunk)

    digests = calculate_hashes(f)
    assert len(digests["sha256"]) == 64
    assert len(digests["sha512"]) == 128


def test_verify_hash_success(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Integrity Check Payload")
    actual_sha256 = hashlib.sha256(b"Integrity Check Payload").hexdigest()

    res = verify_hash(f, actual_sha256)
    assert res["matched"] is True
    assert res["status"] == "VERIFIED"
    assert res["algorithm"] == "SHA256"


def test_verify_hash_mismatch(tmp_path):
    f = tmp_path / "tampered.txt"
    f.write_text("Genuine Content")
    bogus_sha256 = "0" * 64

    res = verify_hash(f, bogus_sha256)
    assert res["matched"] is False
    assert res["status"] == "FAILED_INTEGRITY_MISMATCH"


def test_hashing_nonexistent_file(tmp_path):
    with pytest.raises(FileAccessError):
        calculate_hashes(tmp_path / "does_not_exist.bin")


def test_batch_hashing_directory(tmp_path):
    d = tmp_path / "batch_dir"
    d.mkdir()
    (d / "f1.txt").write_text("File 1")
    (d / "f2.txt").write_text("File 2")

    batch = hash_directory_batch(d)
    assert batch["total_files"] == 2
    assert len(batch["files"]) == 2
