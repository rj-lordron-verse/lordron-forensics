"""
Unit tests for system diagnostics and passive network lookup.
"""

from lordron.modules.diagnostics.doctor import run_system_diagnostics
from lordron.modules.network_intelligence.inspector import lookup_dns


def test_system_diagnostics_health():
    diag = run_system_diagnostics()
    assert "system" in diag
    assert "dependencies" in diag
    assert "lordron_version" in diag
    assert diag["author"] == "Raj"
    assert diag["brand"] == "LORDRON"


def test_passive_dns_lookup_localhost():
    res = lookup_dns("localhost")
    assert res["domain"] == "localhost"
    assert "127.0.0.1" in res["ipv4_addresses"] or len(res["ipv4_addresses"]) >= 1
