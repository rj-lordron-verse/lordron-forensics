"""
Module 05: Log Analyzer
Parses standard log formats, detects timestamps, groups events, identifies error patterns,
and categorizes severity without making unverified claims of malice.
"""

from __future__ import annotations
import re
import csv
import io
from pathlib import Path
from typing import Dict, Any, List, Optional
from collections import Counter
from lordron.core.paths import validate_file_path
from lordron.core.exceptions import FileAccessError

# Timestamp regex patterns
TIMESTAMP_PATTERNS = [
    # ISO 8601: 2024-03-29T12:00:00 or 2024-03-29 12:00:00
    (re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"), "%Y-%m-%dT%H:%M:%S"),
    # Syslog: Mar 29 12:00:00
    (re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
    # Apache/Nginx: [29/Mar/2024:12:00:00 +0000]
    (re.compile(r"\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]"), "[%d/%b/%Y:%H:%M:%S %z]"),
]

# Suspicious indicators/patterns (treated as anomalies for investigator review)
ERROR_PATTERNS = [
    ("AUTH_FAILURE", re.compile(r"(Failed password|authentication failure|invalid user|pam_authenticate failed)", re.IGNORECASE)),
    ("ROOT_OR_SUDO", re.compile(r"(sudo:|COMMAND=/|session opened for user root)", re.IGNORECASE)),
    ("PERMISSION_DENIED", re.compile(r"(permission denied|access denied|forbidden|403 Forbidden)", re.IGNORECASE)),
    ("SERVER_ERROR", re.compile(r"(internal server error|HTTP/[0-9.]+\"\s+50\d|traceback|panic|segfault)", re.IGNORECASE)),
    ("RESOURCE_NOT_FOUND", re.compile(r"(HTTP/[0-9.]+\"\s+404|No such file or directory)", re.IGNORECASE)),
]


def _extract_timestamp(line: str) -> Optional[str]:
    """Detect and extract timestamp string from a log line."""
    for pattern, _ in TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return None


def _classify_severity(line: str) -> str:
    """Classify message severity level based on log tokens."""
    upper = line.upper()
    if any(k in upper for k in ["CRIT", "EMERG", "ALERT", "FATAL", "PANIC"]):
        return "CRITICAL"
    if any(k in upper for k in ["ERROR", "ERR", "FAIL", "FAILED", "FAILURE"]):
        return "ERROR"
    if any(k in upper for k in ["WARN", "WARNING"]):
        return "WARNING"
    if any(k in upper for k in ["DEBUG", "TRACE"]):
        return "DEBUG"
    return "INFO"


def _normalize_event(line: str) -> str:
    """Normalize repeated lines by stripping timestamps and dynamic digits."""
    s = re.sub(r"^\S+\s+\d+\s+\d+:\d+:\d+", "", line)  # Syslog date
    s = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "", s)  # ISO date
    s = re.sub(r"\bpid=\d+\b", "pid=N", s, flags=re.IGNORECASE)
    s = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "IP_ADDR", s)
    return s.strip()[:150]


def parse_log_file(
    file_path: str | Path,
    min_severity: Optional[str] = None,
    max_lines: int = 50000
) -> Dict[str, Any]:
    """
    Parse text-based log files.
    Extracts events, timestamps, groups occurrences, and highlights anomalies.
    """
    path = validate_file_path(file_path, must_exist=True)

    events: List[Dict[str, Any]] = []
    pattern_matches: Dict[str, int] = {p_name: 0 for p_name, _ in ERROR_PATTERNS}
    normalized_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    malformed_lines = 0

    severity_order = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
    min_sev_level = severity_order.get((min_severity or "DEBUG").upper(), 10)

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for idx, line in enumerate(f, start=1):
                if idx > max_lines:
                    break

                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                ts = _extract_timestamp(stripped)
                if not ts:
                    malformed_lines += 1

                sev = _classify_severity(stripped)
                severity_counts[sev] += 1

                # Pattern detection
                matched_patterns = []
                for p_name, p_regex in ERROR_PATTERNS:
                    if p_regex.search(stripped):
                        pattern_matches[p_name] += 1
                        matched_patterns.append(p_name)

                # Grouping
                norm = _normalize_event(stripped)
                normalized_counts[norm] += 1

                # Filter by minimum severity
                if severity_order.get(sev, 20) >= min_sev_level:
                    events.append({
                        "line_number": idx,
                        "timestamp_raw": ts or "(unknown)",
                        "severity": sev,
                        "patterns_detected": matched_patterns,
                        "raw_message": stripped[:300],
                    })

    except OSError as exc:
        raise FileAccessError(f"Error reading log file '{path}': {exc}") from exc

    # Top recurring patterns
    top_recurring = [
        {"pattern": norm_text, "occurrences": count}
        for norm_text, count in normalized_counts.most_common(10)
    ]

    return {
        "file_name": path.name,
        "total_lines_processed": len(events) + malformed_lines,
        "valid_events_parsed": len(events),
        "lines_without_recognized_timestamp": malformed_lines,
        "severity_summary": dict(severity_counts),
        "anomaly_patterns_detected": pattern_matches,
        "top_recurring_events": top_recurring,
        "events": events[:1000],  # Return up to first 1000 for output
        "interpretation_disclaimer": (
            "Detected patterns and anomalies reflect log heuristics only. "
            "They do not constitute definitive proof of malicious activity without independent corroboration."
        )
    }


def export_log_analysis_csv(analysis: Dict[str, Any]) -> str:
    """Format log events as standard CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Line", "Timestamp", "Severity", "Patterns", "Message"])
    for ev in analysis.get("events", []):
        writer.writerow([
            ev.get("line_number"),
            ev.get("timestamp_raw"),
            ev.get("severity"),
            ";".join(ev.get("patterns_detected", [])),
            ev.get("raw_message"),
        ])
    return output.getvalue()
