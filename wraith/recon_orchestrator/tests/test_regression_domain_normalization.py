import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest, ToolResults, ToolStatus

@pytest.mark.asyncio
async def test_regression_domain_normalization():
    orchestrator = ReconOrchestrator()

    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["chyowe.com"]
    mock_graph.create_scan_session.return_value = {"id": "legacy_scan_id"}
    mock_graph.list_recon_sessions.return_value = []

    # Mock tool runs to succeed immediately with empty ToolResults
    for tool in orchestrator.tools:
        tool.run = AsyncMock(return_value=ToolResults())

    with patch("app.orchestrator.graph_client", mock_graph):
        request = ReconRequest(program_id="p1", domains=["https://chyowe.com"])
        res = await orchestrator.start_session(request)
        session_id = res["session_id"]

        # Wait for background task to complete
        timeout = 5
        start_time = asyncio.get_event_loop().time()
        while orchestrator.sessions[session_id].status in ["accepted", "running"]:
            await asyncio.sleep(0.1)
            if asyncio.get_event_loop().time() - start_time > timeout:
                break

        session = orchestrator.sessions[session_id]

        # Check that there is exactly ONE tool_statuses entry per tool
        # e.g., "subfinder:chyowe.com", NOT "subfinder:https://chyowe.com"
        expected_keys = {f"{tool.name}:chyowe.com" for tool in orchestrator.tools}
        assert set(session.tool_statuses.keys()) == expected_keys

        # Check all are completed (i.e., transitioned from PENDING -> RUNNING -> COMPLETED)
        for key, status in session.tool_statuses.items():
            assert status == ToolStatus.COMPLETED
