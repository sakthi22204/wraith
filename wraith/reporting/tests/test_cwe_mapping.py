import pytest
from app.mapping.cwe_mapping import get_mapping

def test_get_mapping_known():
    res = get_mapping("sqli")
    assert res["cwe_id"] == "CWE-89"
    assert "Injection" in res["owasp_category"]

def test_get_mapping_unknown():
    res = get_mapping("magic_vuln")
    assert res["cwe_id"] == "Unknown"
