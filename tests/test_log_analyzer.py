"""
Unit tests for log analyzer, pattern heuristics, and CSV export.
"""

from lordron.modules.log_analyzer.parser import parse_log_file, export_log_analysis_csv


def test_parse_auth_log(sample_log_file):
    res = parse_log_file(sample_log_file)
    assert res["total_lines_processed"] == 4
    assert res["anomaly_patterns_detected"]["AUTH_FAILURE"] >= 2
    assert res["anomaly_patterns_detected"]["ROOT_OR_SUDO"] >= 1


def test_export_log_csv(sample_log_file):
    res = parse_log_file(sample_log_file)
    csv_str = export_log_analysis_csv(res)
    assert "Timestamp" in csv_str
    assert "Failed password" in csv_str
