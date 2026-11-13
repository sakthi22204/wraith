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

def test_get_mapping_for_the_skill_pack_families():
    """The access-control pack files its class by family name; leaving it
    unmapped renders the write-IDOR report as "Unknown - Unknown"."""
    idor = get_mapping("Broken Access Control")
    assert idor["cwe_id"] == "CWE-639"
    assert "Broken Access Control" in idor["owasp_category"]

    logic = get_mapping("Business Logic Flaw")
    assert logic["cwe_id"] == "CWE-840"

def test_recon_exposure_families_are_mapped():
    info = get_mapping("Information Exposure")
    assert info["cwe_id"] == "CWE-200"
    assert "Broken Access Control" in info["owasp_category"]

    err = get_mapping("Error Message Disclosure")
    assert err["cwe_id"] == "CWE-209"
    assert "Security Misconfiguration" in err["owasp_category"]

def test_boolean_blind_sqli_renders_as_cwe_89():
    """The generator emits the technique in the vuln_type; the report must still
    name CWE-89 rather than "Unknown - Unknown"."""
    res = get_mapping("SQL Injection (boolean-blind)")
    assert res["cwe_id"] == "CWE-89"
    assert "Injection" in res["owasp_category"]
