import pytest
from httpx import AsyncClient
from app.main import app
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_recon_start_api():
    async with AsyncClient(transport=AsyncMock(), base_url="http://test") as ac:
        # Actually I should use the app
        pass

    from httpx import ASGITransport
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with patch("app.orchestrator.orchestrator.start_session") as mock_start:
            mock_start.return_value = "test-session-id"

            response = await ac.post("/api/v1/recon/start", json={
                "program_id": "prog_123",
                "domains": ["example.com"]
            })

    assert response.status_code == 202
    assert response.json()["session_id"] == "test-session-id"

@pytest.mark.asyncio
async def test_recon_status_api():
    from app.orchestrator import orchestrator
    from app.schemas import ReconSessionStatus, ToolStatus
    from httpx import ASGITransport

    session_id = "test-session-123"
    orchestrator.sessions[session_id] = ReconSessionStatus(
        session_id=session_id,
        program_id="prog_123",
        status="running",
        tool_statuses={"subfinder:example.com": ToolStatus.RUNNING},
        progress=50.0
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get(f"/api/v1/recon/{session_id}/status")

    assert response.status_code == 200
    assert response.json()["status"] == "running"
    assert response.json()["progress"] == 50.0
