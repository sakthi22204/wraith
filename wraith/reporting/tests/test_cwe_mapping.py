import importlib.util
import json
import sys
from pathlib import Path

import pytest
from app.mapping.cwe_mapping import get_mapping

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


router = _load_module(
    REPO_ROOT / "exploit_agent" / "app" / "skills" / "router.py",
    "wraith_skill_router",
)
builder = _load_module(
    REPO_ROOT / "scripts" / "build_skill_index.py",
    "wraith_build_skill_index",
)

EXPANSION_SKILLS = (
    "hunt-ldap-injection",
    "hunt-xpath-injection",
    "hunt-graphql-injection",
    "hunt-orm-hql-injection",
    "hunt-argument-injection",
    "hunt-code-injection",
    "hunt-eval-injection",
    "hunt-client-template-injection",
    "hunt-el-ognl-injection",
    "hunt-deserialization-injection",
    "hunt-crlf-injection",
    "hunt-xml-injection",
    "hunt-ssi-injection",
    "hunt-latex-injection",
    "hunt-log-injection",
    "hunt-dll-injection",
    "hunt-process-injection",
    "hunt-browser-js",
    "hunt-oob-interaction",
    "hunt-smtp-header-injection",
    "hunt-csv-injection",
    "hunt-dom-clobbering",
    "hunt-css-injection",
    "hunt-websocket-csrf",
)

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


@pytest.mark.parametrize("label, cwe_id, owasp", [
    ("LDAP Injection", "CWE-90", "A03:2021-Injection"),
    ("XPath Injection", "CWE-643", "A03:2021-Injection"),
    ("GraphQL Injection", "CWE-74", "A03:2021-Injection"),
    ("ORM-HQL Injection", "CWE-89", "A03:2021-Injection"),
    ("HQL Injection", "CWE-89", "A03:2021-Injection"),
    ("Argument Injection", "CWE-88", "A03:2021-Injection"),
    ("Code Injection", "CWE-94", "A03:2021-Injection"),
    ("Eval Injection", "CWE-95", "A03:2021-Injection"),
    ("Client-Side Template Injection", "CWE-1336", "A03:2021-Injection"),
    ("Expression Language Injection", "CWE-917", "A03:2021-Injection"),
    ("OGNL Injection", "CWE-917", "A03:2021-Injection"),
    ("Deserialization Injection", "CWE-502", "A08:2021-Software and Data Integrity Failures"),
    ("CRLF Injection", "CWE-113", "A03:2021-Injection"),
    ("HTTP Response Splitting", "CWE-113", "A03:2021-Injection"),
    ("Generic XML Injection", "CWE-91", "A03:2021-Injection"),
    ("SSI Injection", "CWE-97", "A03:2021-Injection"),
    ("LaTeX Injection", "CWE-94", "A03:2021-Injection"),
    ("Log Injection", "CWE-117", "A09:2021-Security Logging and Monitoring Failures"),
    ("DLL Injection", "CWE-427", "A03:2021-Injection"),
    ("Process Injection", "CWE-94", "A03:2021-Injection"),
    ("Browser JS Execution", "CWE-79", "A03:2021-Injection"),
    ("OOB Interaction", "CWE-918", "A10:2021-Server-Side Request Forgery"),
    ("SMTP Header Injection", "CWE-93", "A03:2021-Injection"),
    ("CSV Formula Injection", "CWE-1236", "A03:2021-Injection"),
    ("DOM Clobbering", "CWE-79", "A03:2021-Injection"),
    ("CSS Injection", "CWE-79", "A03:2021-Injection"),
    ("WebSocket CSRF", "CWE-352", "A01:2021-Broken Access Control"),
    ("WebSocket CSWSH", "CWE-352", "A01:2021-Broken Access Control"),
])
def test_expanded_classes_render_real_report_labels(label, cwe_id, owasp):
    mapping = get_mapping(label)
    assert mapping["cwe_id"] == cwe_id
    assert mapping["owasp_category"] == owasp
    assert mapping["cvss_template"].startswith("CVSS:3.1/")


@pytest.mark.parametrize("vuln_type, expected", [
    ("LDAP Injection", "hunt-ldap-injection"),
    ("XPath Injection", "hunt-xpath-injection"),
    ("GraphQL Injection", "hunt-graphql-injection"),
    ("HQL Injection", "hunt-orm-hql-injection"),
    ("Argument Injection", "hunt-argument-injection"),
    ("Code Injection", "hunt-code-injection"),
    ("Eval Injection", "hunt-eval-injection"),
    ("Client-Side Template Injection", "hunt-client-template-injection"),
    ("Expression Language Injection", "hunt-el-ognl-injection"),
    ("Deserialization Injection", "hunt-deserialization-injection"),
    ("CRLF Injection", "hunt-crlf-injection"),
    ("XML Injection", "hunt-xml-injection"),
    ("SSI Injection", "hunt-ssi-injection"),
    ("LaTeX Injection", "hunt-latex-injection"),
    ("Log Injection", "hunt-log-injection"),
    ("DLL Injection", "hunt-dll-injection"),
    ("Process Injection", "hunt-process-injection"),
    ("Browser JS Execution", "hunt-browser-js"),
    ("OOB Interaction", "hunt-oob-interaction"),
    ("SMTP Header Injection", "hunt-smtp-header-injection"),
    ("CSV Formula Injection", "hunt-csv-injection"),
    ("DOM Clobbering", "hunt-dom-clobbering"),
    ("CSS Injection", "hunt-css-injection"),
    ("WebSocket CSRF", "hunt-websocket-csrf"),
])
def test_expanded_classes_route_to_the_matching_local_skill(vuln_type, expected):
    state = {
        "current_graph_snapshot": {
            "nodes": [
                {"labels": ["Finding"], "properties": {"vuln_type": vuln_type}}
            ]
        }
    }
    result = router.route_skills(
        state, "reasoning", set(EXPANSION_SKILLS), max_skills=4)

    assert expected in result.names


def test_expanded_skills_state_the_evidence_standard():
    for name in EXPANSION_SKILLS:
        text = (
            REPO_ROOT / "exploit_agent" / "skills_local" / name / "SKILL.md"
        ).read_text(encoding="utf-8")
        statement = " ".join(text.split())
        assert "LLM output alone is never evidence" in statement
        assert "deterministic harness/runtime observation is required" in statement


def test_index_generator_includes_all_expanded_local_skills(tmp_path, monkeypatch):
    output = tmp_path / "skill_index.json"
    monkeypatch.setattr(builder, "OUT_PATH", output)

    assert builder.main() == 0
    data = json.loads(output.read_text(encoding="utf-8"))
    by_name = {entry["name"]: entry for entry in data["skills"]}

    for name in EXPANSION_SKILLS:
        assert by_name[name]["source"] == "local"
        assert by_name[name]["path"].startswith("exploit_agent/skills_local/")
        assert by_name[name]["keywords"]


def test_committed_index_includes_all_expanded_local_skills():
    data = json.loads(
        (REPO_ROOT / "active_exploit_runner" / "app" / "skill_index.json")
        .read_text(encoding="utf-8")
    )
    names = {entry["name"] for entry in data["skills"]}
    assert set(EXPANSION_SKILLS) <= names
