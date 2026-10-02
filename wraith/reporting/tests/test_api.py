import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
from app.main import app
from app.config import settings

client = TestClient(app)

@pytest.mark.asyncio
async def test_authentication():
    with patch("app.api.routes.graph_db_client", new_callable=AsyncMock) as mock_graph, \
         patch("app.api.routes.generator.generate_finding_report", new_callable=AsyncMock) as mock_gen, \
         patch("app.api.routes.generator.generate_program_report", new_callable=AsyncMock) as mock_gen_prog:

        # Mock some returns to avoid internal errors after auth pass
        mock_graph.get_finding.return_value = {"id": "f1"}
        mock_graph.get_program.return_value = {"name": "Test"}

        from app.models import ReportFinding, ProgramReport
        from datetime import datetime
        mock_gen.return_value = ReportFinding(
            title="T", vulnerability_type="V", severity="S", cvss_score="C",
            ai_confidence="0.9",
            affected_asset="A", description="D", steps_to_reproduce="ST",
            exploit_poc="P", evidence="E", business_impact="B",
            suggested_remediation="R", discovery_metadata={"timestamp": "2023", "tool": "T", "program": "P", "confidence": "0.9", "status": "S"}
        )
        mock_gen_prog.return_value = ProgramReport(program_name="Test", generated_at=datetime.utcnow(), findings=[])

        # Test endpoints that require authentication
        endpoints = [
            ("/api/v1/reports/p1/findings/f1?format=markdown"),
            ("/api/v1/reports/p1?format=markdown")
        ]

        for path in endpoints:
            # No token
            response = client.get(path)
            assert response.status_code == 401

            # Wrong token
            headers = {"Authorization": "Bearer wrong-token"}
            response = client.get(path, headers=headers)
            assert response.status_code == 401

            # Correct token (will fail with other errors like 404, but not 401)
            headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
            response = client.get(path, headers=headers)
            assert response.status_code != 401

@pytest.mark.asyncio
async def test_get_finding_report_markdown():
    with patch("app.api.routes.graph_db_client", new_callable=AsyncMock) as mock_graph, \
         patch("app.api.routes.generator.generate_finding_report", new_callable=AsyncMock) as mock_gen:

        mock_graph.get_findings_for_program.return_value = [{"id": "f1"}]
        mock_graph.get_program.return_value = {"name": "Test"}

        from app.models import ReportFinding
        mock_gen.return_value = ReportFinding(
            title="T", vulnerability_type="V", severity="S", cvss_score="C",
            ai_confidence="0.9",
            affected_asset="A", description="D", steps_to_reproduce="ST",
            exploit_poc="P", evidence="E", business_impact="B",
            suggested_remediation="R", discovery_metadata={"timestamp": "2023", "tool": "T", "program": "P", "confidence": "0.9", "status": "S"}
        )

        headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
        response = client.get("/api/v1/reports/p1/findings/f1?format=markdown", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/markdown; charset=utf-8"
        # No validation_state means no confirmation evidence, so the heading must
        # not read as a confirmed finding.
        assert "# Unvalidated Hypothesis: T" in response.text
        assert "# Finding: T" not in response.text

        # The confirmed case still renders as a finding.
        mock_gen.return_value = mock_gen.return_value.model_copy(update={"validation_state": "CONFIRMED"})
        confirmed = client.get("/api/v1/reports/p1/findings/f1?format=markdown", headers=headers)
        assert "# Finding: T" in confirmed.text
        assert "# Unvalidated Hypothesis: T" not in confirmed.text

@pytest.mark.asyncio
async def test_get_program_report_pdf():
    with patch("app.api.routes.generator.generate_program_report", new_callable=AsyncMock) as mock_gen, \
         patch("app.api.routes.pdf_exporter.export_report") as mock_pdf:

        from app.models import ProgramReport
        from datetime import datetime
        mock_gen.return_value = ProgramReport(program_name="Test", generated_at=datetime.utcnow(), findings=[])
        mock_pdf.return_value = b"%PDF-mock"

        headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
        response = client.get("/api/v1/reports/p1?format=pdf", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content == b"%PDF-mock"

def test_parse_date():
    from app.api.routes import parse_date
    from datetime import datetime

    # Valid string
    d1 = parse_date("2023-10-01T12:00:00Z")
    assert d1.year == 2023
    assert d1.month == 10
    assert d1.day == 1

    # Invalid string
    with patch("app.api.routes.logger.warning") as mock_warn:
        d2 = parse_date("invalid-date-string")
        assert isinstance(d2, datetime)
        mock_warn.assert_called_once()
        assert "Malformed ISO date string" in mock_warn.call_args[0][0]

    # Empty string or None
    d3 = parse_date("")
    assert isinstance(d3, datetime)
    d4 = parse_date(None)
    assert isinstance(d4, datetime)
