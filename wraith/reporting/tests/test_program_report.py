import pytest
from unittest.mock import AsyncMock, patch
from app.generator import generator

@pytest.fixture
def mock_clients():
    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as mock_graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as mock_audit:
        yield mock_graph, mock_audit

@pytest.mark.asyncio
async def test_generate_program_report_filtering(mock_clients):
    mock_graph, mock_audit = mock_clients

    findings = [
        {"id": "f1", "status": "AI_VALIDATED", "vuln_type": "xss", "severity": "high"},
        {"id": "f2", "status": "DUPLICATE", "vuln_type": "xss"},
        {"id": "f3", "status": "FALSE_POSITIVE", "vuln_type": "sqli"},
        {"id": "f4", "status": "DUPLICATE", "vuln_type": "idor"}
    ]

    mock_graph.get_findings_for_program.return_value = findings
    mock_graph.get_program.return_value = {"name": "Test Program"}
    mock_graph.get_target_details.return_value = None
    mock_graph.get_discovering_tool.return_value = None
    mock_audit.get_audit_entries.return_value = []

    report = await generator.generate_program_report("p1")

    # Assert f1 is the only one included
    assert len(report.findings) == 1
    assert report.findings[0].discovery_metadata["status"] == "AI_VALIDATED"

    # Assert summary line
    assert "2 duplicate and 1 false-positive" in report.summary_line


@pytest.mark.asyncio
async def test_generate_program_report_merges_same_endpoint_sqli_variants(mock_clients):
    """Union/boolean/generic probes of one parameter are one report finding."""
    mock_graph, mock_audit = mock_clients
    common = {
        "status": "AI_VALIDATED",
        "target_id": "endpoint-1",
        "poc_request": "GET http://shop.test/rest/products/search?q=x",
        "poc_response": "200 OK",
        "expected_result": "query changes",
        "actual_result": "query changed",
        "confidence": "0.9",
    }
    findings = [
        {
            **common, "id": "union", "title": "UNION injection",
            "vuln_type": "SQL Injection (union-based)", "severity": "high",
            "validation_stage": "IMPACT_CONFIRMED",
            "evidence": "union canary returned",
        },
        {
            **common, "id": "boolean", "title": "Boolean injection",
            "vuln_type": "SQL Injection (boolean-blind)", "severity": "critical",
            "validation_stage": "CONDITION_CONFIRMED",
            "evidence": "true/false responses differed",
        },
        {
            **common, "id": "generic", "title": "Query injection",
            "vuln_type": "SQL Injection", "severity": "critical",
            "validation_stage": "CONDITION_CONFIRMED",
            "evidence": "baseline comparison differed",
        },
    ]
    mock_graph.get_findings_for_program.return_value = findings
    mock_graph.get_program.return_value = {"name": "Test Program"}
    mock_graph.get_target_details.return_value = None
    mock_graph.get_discovering_tool.return_value = None
    mock_audit.get_audit_entries.return_value = []

    report = await generator.generate_program_report("p1")

    assert len(report.findings) == 1
    merged = report.findings[0]
    # The report derives a conservative 8.8 vector for authenticated SQL
    # injection, so its severity is the CVSS band (High) rather than the raw
    # graph label (Critical).
    assert merged.severity == "High"
    assert merged.cvss_score == "8.8 (High)"
    assert merged.cvss_provisional is True
    assert merged.title == "UNION injection"
    assert "boolean-blind" in merged.description
    assert "2 duplicate" in report.summary_line


@pytest.mark.asyncio
async def test_injection_canary_is_not_reported_as_a_vulnerability(mock_clients):
    """A canary proves input reaches an interpreter; it does not name the bug."""
    mock_graph, mock_audit = mock_clients
    findings = [
        {"id": "canary", "status": "AI_VALIDATED", "vuln_type": "Injection Canary",
         "severity": "critical", "title": "Injection canary fired",
         "poc_request": "GET http://x.test/?q=canary",
         "poc_response": "200 OK"},
        {"id": "real", "status": "AI_VALIDATED", "vuln_type": "SQL Injection",
         "severity": "high", "title": "SQL injection"},
    ]
    mock_graph.get_findings_for_program.return_value = findings
    mock_graph.get_program.return_value = {"name": "Test Program"}
    mock_graph.get_target_details.return_value = None
    mock_graph.get_discovering_tool.return_value = None
    mock_audit.get_audit_entries.return_value = []

    report = await generator.generate_program_report("p1")

    assert [f.title for f in report.findings] == ["SQL injection"]


def test_endpoint_display_keeps_payload_out_of_the_summary_table():
    """A reflected payload contains spaces; the table must show a usable URL,
    not the truncated ``?name=<img`` fragment produced by a \S+ regex."""
    from app.generator import _endpoints_from_evidence

    finding = {
        "poc_request": (
            "GET http://dvwa/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>\n"
            "Cookie: PHPSESSID=[REDACTED]; security=[REDACTED]"
        )
    }
    assert _endpoints_from_evidence(finding, "") == [
        "http://dvwa/vulnerabilities/xss_r/?name=..."
    ]
