import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest

@pytest.mark.asyncio
async def test_start_recon_deduplication():
    orchestrator = ReconOrchestrator()

    mock_graph = AsyncMock()
    # Mocking returning a list of dictionaries as returned by API client
    mock_graph.list_recon_sessions.return_value = [
        {"id": "existing_id", "status": "running", "domains": ["example.com"]}
    ]
    mock_graph.get_program_scope.return_value = ["example.com"]

    with patch("app.orchestrator.graph_client", mock_graph):
        request = ReconRequest(program_id="p1", domains=["example.com"])
        res = await orchestrator.start_session(request)

        assert res["session_id"] == "existing_id"
        assert res["duplicate_of"] == "existing_id"
        # Verify no new session was added to in-memory dict (it would have a random UUID)
        assert "existing_id" not in orchestrator.sessions

@pytest.mark.asyncio
async def test_start_recon_new_session_after_completion():
    orchestrator = ReconOrchestrator()

    mock_graph = AsyncMock()
    mock_graph.list_recon_sessions.return_value = [
        {"id": "old_id", "status": "completed", "domains": ["example.com"]}
    ]
    mock_graph.get_program_scope.return_value = ["example.com"]
    mock_graph.create_recon_session.return_value = {"id": "new_id"}

    with patch("app.orchestrator.graph_client", mock_graph):
        request = ReconRequest(program_id="p1", domains=["example.com"])
        res = await orchestrator.start_session(request)

        assert res["session_id"] != "old_id"
        assert "duplicate_of" not in res
