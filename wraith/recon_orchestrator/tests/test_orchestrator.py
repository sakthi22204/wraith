import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest, ToolResults, HostResult

@pytest.mark.asyncio
async def test_orchestrator_parallelism():
    orchestrator = ReconOrchestrator()

    # Mock each tool's run method to have a delay
    async def slow_run(*args, **kwargs):
        await asyncio.sleep(1)
        return ToolResults(hosts=[HostResult(value="test.com", source_tool="mock")])

    for tool in orchestrator.tools:
        tool.run = AsyncMock(side_effect=slow_run)

    # Mock graph client to avoid real HTTP calls
    with patch("app.orchestrator.graph_client.upsert_host", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as mock_scope:
        mock_scope.return_value = ["example.com"]
        start_time = time.time()

        request = ReconRequest(program_id="test_prog", domains=["example.com"])
        res = await orchestrator.start_session(request)
        session_id = res["session_id"]

        # Wait for background tasks to finish
        # In a real test we'd need a better way to wait for session completion
        while orchestrator.sessions[session_id].status != "completed":
            await asyncio.sleep(0.1)
            if time.time() - start_time > 5:
                pytest.fail("Test timed out")

        end_time = time.time()
        elapsed = end_time - start_time

        # We have 4 tools running in parallel, each takes 1s.
        # Total time should be close to 1s, definitely less than 2s.
        assert elapsed < 2.0
        assert elapsed >= 1.0
