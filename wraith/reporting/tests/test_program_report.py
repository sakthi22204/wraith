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
