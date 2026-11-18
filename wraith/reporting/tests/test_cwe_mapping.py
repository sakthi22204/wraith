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

def test_scanner_template_suffix_is_stripped_before_lookup():
    """Recon hypotheses carry the nuclei template action ("Public Swagger API -
    Detect"); the suffix is not part of the weakness and must not blank the
    mapping."""
    res = get_mapping("Public Swagger API - Detect")
    assert res["cwe_id"] == "CWE-200"
    assert "Security Misconfiguration" in res["owasp_category"]

    assert get_mapping("Public Swagger API - Matcher")["cwe_id"] == "CWE-200"

def test_stripping_the_suffix_does_not_invent_a_mapping():
    assert get_mapping("Magic Vuln - Detect")["cwe_id"] == "Unknown"

@pytest.mark.parametrize("vuln_type,cwe", [
    ("swagger-api", "CWE-200"),
    ("http-missing-security-headers", "CWE-693"),
    ("open-proxy-internal", "CWE-441"),
    ("Sensitive Data Exposure", "CWE-200"),
    ("Business Logic", "CWE-840"),
    ("Authentication Bypass Retest", "CWE-287"),
])
def test_scanner_slug_vuln_types_are_mapped(vuln_type, cwe):
    """Nuclei ids and recon rule names land in the graph as vuln_type and used
    to render as "Unknown - Unknown" in the weakness block."""
    assert get_mapping(vuln_type)["cwe_id"] == cwe

def test_family_aliases_name_the_weakness_class():
    """The validation packs use family names; aliases must resolve them."""
    assert get_mapping("Stored XSS")["cwe_id"] == "CWE-79"
    assert get_mapping("Reflected XSS")["cwe_id"] == "CWE-79"
    assert get_mapping("Command Injection")["cwe_id"] == "CWE-77"
    assert get_mapping("Local File Inclusion")["cwe_id"] == "CWE-22"
    assert get_mapping("Blind SQL Injection")["cwe_id"] == "CWE-89"
