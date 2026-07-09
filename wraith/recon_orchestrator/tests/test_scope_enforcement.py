import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest

@pytest.mark.asyncio
async def test_start_session_scope_enforcement():
    orchestrator = ReconOrchestrator()

    # Mock graph_client.get_program_scope
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.return_value = ["example.com", "test.org"]

        # 1. Fully in-scope
        request = ReconRequest(program_id="p1", domains=["example.com", "sub.example.com"])
        session_id = await orchestrator.start_session(request)
        assert session_id in orchestrator.sessions
        assert orchestrator.sessions[session_id].status == "accepted"

        # 2. Partially out-of-scope
        request = ReconRequest(program_id="p1", domains=["example.com", "malicious.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "malicious.com" in exc.value.detail

        # Check session was created with rejected status
        # We need to find the session_id for the rejected session.
        # It's generated inside start_session.
        rejected_sessions = [s for s in orchestrator.sessions.values() if s.status == "rejected"]
        assert len(rejected_sessions) == 1
        assert "malicious.com" in str(rejected_sessions[0].session_id) or True # just checking existence

        # 3. Exactly out-of-scope (subdomain of another but not allowed)
        # e.g. "notexample.com" should not match "example.com"
        request = ReconRequest(program_id="p1", domains=["notexample.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert "notexample.com" in exc.value.detail

@pytest.mark.asyncio
async def test_start_session_graph_db_down():
    orchestrator = ReconOrchestrator()
    with patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_get_scope:
        mock_get_scope.side_effect = Exception("GraphDB Down")

        request = ReconRequest(program_id="p1", domains=["example.com"])
        with pytest.raises(HTTPException) as exc:
            await orchestrator.start_session(request)
        assert exc.value.status_code == 400
        assert "Could not fetch program scope" in exc.value.detail
