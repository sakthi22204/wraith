import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.generator import generator
from datetime import datetime

@pytest.fixture
def mock_clients():
    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as mock_graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as mock_audit:
        yield mock_graph, mock_audit

@pytest.mark.asyncio
async def test_generate_finding_report_full(mock_clients):
    mock_graph, mock_audit = mock_clients

    finding = {
        "id": "f1",
        "vuln_type": "sqli",
        "severity": "high",
        "confidence": "0.9",
        "status": "AI_VALIDATED",
        "description": "SQL injection in search",
        "discovered_at": "2023-01-01T12:00:00Z",
        "target_id": "t1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "evidence": "SELECT * FROM users WHERE id = '1' --"
    }

    mock_graph.get_target_details.return_value = {
        "id": "t1",
        "labels": ["Endpoint"],
        "properties": {"url": "http://test.com/search"},
        "host": "test.com"
    }
    mock_graph.get_discovering_tool.return_value = {"name": "sqlmap"}
    mock_graph.get_program.return_value = {"name": "Test Program"}

    mock_audit.get_audit_entries.return_value = [
        {"action": "run_sqlmap", "result": "Success"}
    ]

    report = await generator.generate_finding_report("p1", finding)

    assert report.title == "SQLI in SQL injection in search"
    assert "CWE-89" in report.vulnerability_type
    assert report.severity == "High"
    assert "9.8" in report.cvss_score
    assert report.ai_confidence == "0.9"
    assert "Host: test.com" in report.affected_asset
    assert "sqlmap" in report.steps_to_reproduce
    # This finding carries no executed evidence, so the report must say the PoC
    # was never proven rather than dressing a sqlmap discovery run up as an
    # exploit attempt.
    assert "No executed proof of concept" in report.exploit_poc
    assert "Recorded exploit attempt" not in report.exploit_poc
    assert "SELECT" in report.evidence
    assert "Test Program" in report.discovery_metadata["program"]


@pytest.mark.asyncio
async def test_generate_finding_report_renders_executed_evidence(mock_clients):
    """A validated finding must render the request and response that were seen."""
    mock_graph, mock_audit = mock_clients

    finding = {
        "id": "f2",
        "title": "Unauthenticated Prometheus Metrics Endpoint Exposed",
        "vuln_type": "Info Disclosure",
        "severity": "medium",
        "confidence": "0.9",
        "status": "AI_VALIDATED",
        "description": "Scanner reported a /metrics endpoint exposing counters.",
        "discovered_at": "2023-01-01T12:00:00Z",
        "target_id": "t1",
        "validation_stage": "IMPACT_CONFIRMED",
        "poc_request": "GET http://juice_shop:3000/metrics",
        "poc_response": "HTTP 200\ncontent-type: text/plain\n\n# HELP juiceshop_metric",
        "expected_result": "body contains '# HELP'",
        "actual_result": "body contains '# HELP' (26096 bytes)",
        "steps_to_reproduce": "GET http://juice_shop:3000/metrics with no credentials.",
        "root_cause": "The metrics route is not placed behind authentication.",
        "impact": "Internal telemetry is disclosed to any unauthenticated caller.",
        "remediation": "Require authentication for the /metrics route.",
    }

    mock_graph.get_target_details.return_value = {
        "id": "t1",
        "labels": ["Endpoint"],
        "properties": {"url": "http://juice_shop:3000"},
        "host": "juice_shop",
    }
    mock_graph.get_discovering_tool.return_value = {"name": "nuclei"}
    mock_graph.get_program.return_value = {"name": "JuiceShop"}
    mock_audit.get_audit_entries.return_value = []

    report = await generator.generate_finding_report("p1", finding)

    # The recorded title is used verbatim.
    assert report.title == "Unauthenticated Prometheus Metrics Endpoint Exposed"
    # The real exchange, not a reconstruction.
    assert "GET http://juice_shop:3000/metrics" in report.steps_to_reproduce
    assert "GET http://juice_shop:3000/metrics" in report.exploit_poc
    assert "# HELP juiceshop_metric" in report.exploit_poc
    assert "IMPACT_CONFIRMED" in report.exploit_poc
    # Expected vs actual, and the analyst's own impact/remediation rather than a
    # severity-template guess.
    assert "body contains '# HELP'" in report.steps_to_reproduce
    assert "Internal telemetry is disclosed" in report.business_impact
    assert "Require authentication for the /metrics route." in report.suggested_remediation
    # The timeline records the validation exchange itself.
    assert any("IMPACT_CONFIRMED" in e.get("event", "") for e in report.timeline)
