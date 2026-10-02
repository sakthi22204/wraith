import pytest
import asyncio
import time
from unittest.mock import AsyncMock, patch
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest, ToolResults, HostResult

# The orchestrator reports progress to graph_db throughout a run: it registers
# the session, marks it running, and updates it as tools finish. Left real, those
# calls go to a live graph_api with a fabricated investigation id, which answers
# 500, and the orchestrator then retries with 2s and 4s backoffs -- so the test
# measured its own backoff schedule instead of its tools' concurrency, and a
# graph_api that happened to be down turned it into an indefinite hang.
@pytest.fixture
def isolated_graph():
    with patch("app.orchestrator.graph_client.upsert_host", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.upsert_port", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.upsert_endpoint", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.create_recon_session", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.create_scan_session", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.update_recon_session", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.update_scan_session", new_callable=AsyncMock), \
         patch("app.orchestrator.graph_client.list_recon_sessions", new_callable=AsyncMock, return_value=[]), \
         patch("app.orchestrator.graph_client.get_program_scope", new_callable=AsyncMock) as scope:
        scope.return_value = ["example.com"]
        yield


@pytest.mark.asyncio
async def test_orchestrator_parallelism(isolated_graph):
    orchestrator = ReconOrchestrator()

    # Mock each tool's run method to have a delay
    async def slow_run(*args, **kwargs):
        await asyncio.sleep(0.5)
        return ToolResults(hosts=[HostResult(value="test.com", source_tool="mock")])

    for tool in orchestrator.tools:
        tool.run = AsyncMock(side_effect=slow_run)

    # Graph calls are stubbed by the isolated_graph fixture.
    start_time = time.time()

    request = ReconRequest(program_id="test_prog", domains=["example.com"])
    res = await orchestrator.start_session(request)
    session_id = res["session_id"]

    # Wait for background tasks to finish
    while orchestrator.sessions[session_id].status != "completed":
        await asyncio.sleep(0.1)
        if time.time() - start_time > 5:
            pytest.fail(
                f"Test timed out; session status is "
                f"{orchestrator.sessions[session_id].status!r}"
            )

    end_time = time.time()
    elapsed = end_time - start_time

    # Every tool takes 0.5s. Run concurrently that is about 0.5s of wall clock;
    # run one after another it is 0.5s per tool. The point is the second number.
    assert elapsed < 2.0, (
        f"tools appear to have run serially: {elapsed:.2f}s for tools that "
        f"each take 0.5s"
    )
    assert elapsed >= 0.5
