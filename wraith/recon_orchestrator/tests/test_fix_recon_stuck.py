import pytest
import asyncio
import logging
from unittest.mock import AsyncMock, patch, MagicMock
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconSessionStatus, ToolStatus

@pytest.mark.asyncio
async def test_update_recon_session_retry_success():
    orchestrator = ReconOrchestrator()
    session_id = "test-session-123"

    # Setup state
    orchestrator.sessions[session_id] = ReconSessionStatus(
        session_id=session_id,
        program_id="p1",
        status="running",
        tool_statuses={},
        progress=0.0
    )

    # First call (at start with "running") succeeds.
    # Subsequent calls (at end with "completed") fails once, then succeeds.
    call_count = 0
    async def mock_update(sid, status, tool_results=None):
        nonlocal call_count
        if status == "running":
            return

        call_count += 1
        if call_count == 1:
            raise Exception("Transient network issue")
        return

    mock_graph = AsyncMock()
    mock_graph.update_recon_session.side_effect = mock_update
    mock_graph.create_scan_session.return_value = {"id": "legacy_scan_id"}

    with patch("app.orchestrator.graph_client", mock_graph), \
         patch("asyncio.sleep") as mock_sleep:

        # Mock run_session's tool spawning to immediately complete
        with patch.object(orchestrator, "_run_tool", return_value=True):
             await orchestrator.run_session(session_id, "p1", [])

        # Called once for "running" and twice for "completed"
        assert mock_graph.update_recon_session.call_count == 3
        assert mock_sleep.call_count == 1
        mock_sleep.assert_called_with(2.0)

@pytest.mark.asyncio
async def test_update_recon_session_retry_exhausted(caplog):
    orchestrator = ReconOrchestrator()
    session_id = "test-session-456"

    orchestrator.sessions[session_id] = ReconSessionStatus(
        session_id=session_id,
        program_id="p1",
        status="running",
        tool_statuses={},
        progress=0.0
    )

    async def mock_update(sid, status, tool_results=None):
        if status == "running":
            return
        # Always fail for the final status
        raise Exception("Persistent API Down")

    mock_graph = AsyncMock()
    mock_graph.update_recon_session.side_effect = mock_update
    mock_graph.create_scan_session.return_value = {"id": "legacy_scan_id"}

    with patch("app.orchestrator.graph_client", mock_graph), \
         patch("asyncio.sleep") as mock_sleep, \
         caplog.at_level(logging.ERROR, logger="recon_orchestrator"):

        with patch.object(orchestrator, "_run_tool", return_value=True):
             await orchestrator.run_session(session_id, "p1", [])

        # Called once for "running" and 3 times for final status
        assert mock_graph.update_recon_session.call_count == 4
        assert mock_sleep.call_count == 2

        # Verify ERROR-level log is produced containing the session_id
        error_logs = [record.message for record in caplog.records if record.levelno == logging.ERROR]
        assert len(error_logs) == 1
        assert "CRITICAL ERROR" in error_logs[0]
        assert session_id in error_logs[0]
