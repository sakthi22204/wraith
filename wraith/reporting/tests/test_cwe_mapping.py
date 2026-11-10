import pytest
from app.mapping.cwe_mapping import get_mapping

def test_get_mapping_known():
    res = get_mapping("sqli")
    assert res["cwe_id"] == "CWE-89"
    assert "Injection" in res["owasp_category"]

def test_get_mapping_unknown():
    res = get_mapping("magic_vuln")
    assert res["cwe_id"] == "Unknown"

def test_get_mapping_for_the_deterministic_finding_types():
    """The login-bypass and unauthenticated-data rules must not render as
    "Unknown - Unknown": a report that cannot name the weakness class reads as
    an unfinished template, and the class is what tells the reader to fix the
    query versus the access check."""
    auth = get_mapping("Authentication Bypass")
    assert auth["cwe_id"] == "CWE-287"
    assert "Authentication Failures" in auth["owasp_category"]

    pii = get_mapping("PII Exposure")
    assert pii["cwe_id"] == "CWE-359"
    assert "Broken Access Control" in pii["owasp_category"]
