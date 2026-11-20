import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest, ToolStatus

@pytest.mark.asyncio
async def test_session_failure_on_tool_error():
    orchestrator = ReconOrchestrator()

    # Mock graph client to avoid real API calls
    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["example.com"]
    mock_graph.create_scan_session.return_value = {"id": "graph_id"}

    with patch("app.orchestrator.graph_client", mock_graph):
        # Mock tools to fail
        for tool in orchestrator.tools:
            tool.run = AsyncMock(side_effect=Exception("Spawn failed"))

        request = ReconRequest(program_id="p1", domains=["example.com"])
        res = await orchestrator.start_session(request)
        session_id = res["session_id"]

        # Wait for background task to complete
        timeout = 5
        start_time = asyncio.get_event_loop().time()
        while orchestrator.sessions[session_id].status in ["accepted", "running"]:
            await asyncio.sleep(0.1)
            if asyncio.get_event_loop().time() - start_time > timeout:
                break

        status = orchestrator.sessions[session_id].status
        assert status == "failed"
        assert orchestrator.sessions[session_id].progress == 100.0


@pytest.mark.asyncio
async def test_start_session_only_runs_requested_tools():
    orchestrator = ReconOrchestrator()

    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["example.com"]
    mock_graph.create_scan_session.return_value = {"id": "graph_id"}

    with patch("app.orchestrator.graph_client", mock_graph):
        for tool in orchestrator.tools:
            tool.run = AsyncMock(return_value={})

        result = await orchestrator.start_session(
            ReconRequest(program_id="p1", domains=["example.com"], tools=["httpx"])
        )
        session_id = result["session_id"]

        timeout = 5
        start_time = asyncio.get_event_loop().time()
        while orchestrator.sessions[session_id].status in ["accepted", "running"]:
            await asyncio.sleep(0.1)
            if asyncio.get_event_loop().time() - start_time > timeout:
                break

        session = orchestrator.sessions[session_id]
        assert session.tool_statuses["httpx:example.com"] in (
            ToolStatus.COMPLETED, ToolStatus.FAILED, ToolStatus.TIMED_OUT
        )
        assert session.tool_statuses["naabu:example.com"] == ToolStatus.SKIPPED
        assert session.tool_statuses["cloud_enum:example.com"] == ToolStatus.SKIPPED
        assert not any("Starting naabu" in line for line in session.logs)
