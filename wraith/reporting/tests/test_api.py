import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch
from app.main import app

client = TestClient(app)

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

        response = client.get("/reports/p1/findings/f1?format=markdown")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/markdown; charset=utf-8"
        assert "# Finding: T" in response.text

@pytest.mark.asyncio
async def test_get_program_report_pdf():
    with patch("app.api.routes.generator.generate_program_report", new_callable=AsyncMock) as mock_gen, \
         patch("app.api.routes.pdf_exporter.export_report") as mock_pdf:

        from app.models import ProgramReport
        from datetime import datetime
        mock_gen.return_value = ProgramReport(program_name="Test", generated_at=datetime.utcnow(), findings=[])
        mock_pdf.return_value = b"%PDF-mock"

        response = client.get("/reports/p1?format=pdf")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content == b"%PDF-mock"
