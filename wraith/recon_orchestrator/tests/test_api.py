import pytest
from httpx import AsyncClient
from app.main import app
from unittest.mock import AsyncMock, patch

@pytest.mark.asyncio
async def test_recon_start_api():
    from httpx import ASGITransport
    from app.config import settings

    headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with patch("app.orchestrator.orchestrator.start_session") as mock_start:
            mock_start.return_value = {"session_id": "test-session-id"}

            response = await ac.post("/api/v1/recon/start", json={
                "program_id": "prog_123",
                "domains": ["example.com"]
            }, headers=headers)

    assert response.status_code == 202
    assert response.json()["session_id"] == "test-session-id"


@pytest.mark.asyncio
async def test_recon_start_refuses_an_unauthenticated_caller():
    """`/start` spawns tool containers on the host Docker socket.

    An unauthenticated caller here is an unauthenticated container spawn, which
    is why the route carries the admin token even though the orchestrator's own
    broker token is a separate secret used outbound.
    """
    from httpx import ASGITransport

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with patch("app.orchestrator.orchestrator.start_session") as mock_start:
            for headers in ({}, {"Authorization": "Bearer wrong-token"}):
                response = await ac.post("/api/v1/recon/start", json={
                    "program_id": "prog_123",
                    "domains": ["example.com"]
                }, headers=headers)
                assert response.status_code == 401

            mock_start.assert_not_called()


@pytest.mark.asyncio
async def test_recon_cancel_refuses_an_unauthenticated_caller():
    from app.orchestrator import orchestrator
    from app.schemas import ReconSessionStatus
    from httpx import ASGITransport

    session_id = "cancel-auth-test"
    orchestrator.sessions[session_id] = ReconSessionStatus(
        session_id=session_id,
        program_id="prog_123",
        status="running",
        tool_statuses={},
        progress=10.0,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        with patch("app.orchestrator.orchestrator.cancel_session", new=AsyncMock()) as mock_cancel:
            response = await ac.post(f"/api/v1/recon/{session_id}/cancel")
            assert response.status_code == 401
            mock_cancel.assert_not_called()

    orchestrator.sessions.pop(session_id, None)


@pytest.mark.asyncio
async def test_recon_status_is_not_auth_gated():
    """Reads are not gated, so the panel can render progress without a token.

    Asserted as "not 401" rather than on a specific status: an unknown session
    id falls through to graph_db and 404s there, and the point of the test is
    only which layer refuses the caller.
    """
    from httpx import ASGITransport

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/v1/recon/some-session/status")
        assert response.status_code != 401

        listed = await ac.get("/api/v1/recon/sessions?investigation_id=prog_123")
        assert listed.status_code != 401

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
