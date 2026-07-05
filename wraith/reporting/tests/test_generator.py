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
    assert "Recorded exploit attempt" in report.exploit_poc
    assert "SELECT" in report.evidence
    assert "Test Program" in report.discovery_metadata["program"]
