-- LORDRON Forensics SQLite Database Schema v1.0
-- Created by Raj | Brand: LORDRON

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    investigator TEXT NOT NULL,
    description TEXT,
    created_at_utc TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN'
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    original_path TEXT NOT NULL,
    vault_path TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size_bytes INTEGER NOT NULL,
    detected_format TEXT NOT NULL,
    sha256_at_acquisition TEXT NOT NULL,
    sha512_at_acquisition TEXT NOT NULL,
    md5_legacy TEXT NOT NULL,
    acquisition_utc TEXT NOT NULL,
    last_verified_utc TEXT,
    integrity_status TEXT NOT NULL DEFAULT 'ACQUIRED',
    notes TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    author TEXT NOT NULL,
    content TEXT NOT NULL,
    timestamp_utc TEXT NOT NULL,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_logs(case_id);
CREATE INDEX IF NOT EXISTS idx_notes_case ON case_notes(case_id);
