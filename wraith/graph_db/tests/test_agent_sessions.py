import pytest
from unittest.mock import AsyncMock, MagicMock
from app.repository import Neo4jRepository
from app.schema import AgentSession

@pytest.mark.asyncio
async def test_create_agent_session_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = {
        "id": "s1",
        "program_id": "p1",
        "status": "running",
        "iteration_count": 0,
        "tools_used": [],
        "reasoning_log": [],
        "started_at": "2023-01-01T00:00:00Z"
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    session = await repo.create_agent_session("s1", "p1", "running", 0, [], [])

    assert session.id == "s1"
    assert session.status == "running"
    assert mock_session.run.call_count == 1
    args, kwargs = mock_session.run.call_args
    assert "MERGE (s:AgentSession {id: $id})" in args[0]

@pytest.mark.asyncio
async def test_update_agent_session_status_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = {
        "id": "s1",
        "program_id": "p1",
        "status": "completed",
        "iteration_count": 5,
        "tools_used": ["run_nmap_scan"],
        "reasoning_log": ["think"],
        "started_at": "2023-01-01T00:00:00Z",
        "completed_at": "2023-01-01T00:05:00Z"
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    session = await repo.update_agent_session_status("s1", "completed", 5, ["run_nmap_scan"], "report", ["think"])

    assert session.status == "completed"
    assert session.iteration_count == 5
    assert mock_session.run.call_count == 1
    args, kwargs = mock_session.run.call_args
    assert "SET s.status = $status" in args[0]

@pytest.mark.asyncio
async def test_cleanup_orphaned_agent_sessions_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = 3
    mock_result.single.return_value = {"count": 3}
    mock_session.run.return_value = mock_result

    count = await repo.cleanup_orphaned_agent_sessions()
    assert count == 3
    assert mock_session.run.call_count == 1
    args, kwargs = mock_session.run.call_args
    assert "MATCH (s:AgentSession {status: \"running\"})" in args[0]
    assert "SET s.status = \"interrupted\"" in args[0]
