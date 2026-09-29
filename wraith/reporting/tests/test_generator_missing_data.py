import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.generator import generator

@pytest.fixture
def mock_clients():
    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as mock_graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as mock_audit:
        yield mock_graph, mock_audit

@pytest.mark.asyncio
async def test_generate_finding_report_missing_data(mock_clients):
    mock_graph, mock_audit = mock_clients

    finding = {
        "id": "f2",
        "vuln_type": "xss",
        "severity": "medium",
        "confidence": "0.7",
        "status": "UNCONFIRMED",
        "description": "Potential XSS",
        "discovered_at": "2023-01-01T12:00:00Z",
        "target_id": "t2",
        "cvss_vector": None, # Missing
        "evidence": None     # Missing
    }

    mock_graph.get_target_details.return_value = None
    mock_graph.get_discovering_tool.return_value = None
    mock_graph.get_program.return_value = None
    mock_audit.get_audit_entries.return_value = [] # Missing

    report = await generator.generate_finding_report("p1", finding)

    assert "CVSS score not calculated" in report.cvss_score
    assert "Unknown Asset" in report.affected_asset
    # With no executed request there is nothing to replay, so the report must
    # label the finding as an unvalidated hypothesis rather than inventing
    # "reconstructed" steps that nobody performed.
    assert "Not yet validated by an executed request" in report.steps_to_reproduce
    assert "scanner hypothesis" in report.steps_to_reproduce
    assert "Reconstructed steps (best effort)" not in report.steps_to_reproduce
    assert "No proof of concept" in report.exploit_poc
    assert "No raw evidence captured" in report.evidence
    assert report.discovery_metadata["tool"] == "automated scan"
