import pytest
import json
import httpx
from unittest.mock import AsyncMock, MagicMock
from app.main import app
from app.repository import Neo4jRepository
from app.schema import AgentSession
from app.api.routes import get_repo

def _agent_session_record(**overrides):
    record = {
        "id": "s1",
        "investigation_id": "p1",
        "status": "completed",
        "iteration_count": 1,
        "tools_used": ["run_nuclei_scan"],
        "reasoning_log": ["line1", "line2"],
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
        "final_report": "report",
    }
    record.update(overrides)
    return record

@pytest.fixture
def override_repo():
    mock_repo = AsyncMock()
    mock_repo.update_agent_session_status.return_value = _agent_session_record()
    mock_repo.create_agent_session.return_value = _agent_session_record()

    async def _get_repo():
        yield mock_repo

    app.dependency_overrides[get_repo] = _get_repo
    yield mock_repo
    app.dependency_overrides.pop(get_repo, None)

@pytest.mark.asyncio
async def test_update_agent_session_parses_json_list_params(override_repo):
    """Regression: FastAPI 0.141+ no longer collects repeated scalar query params
    into List[str]. The route must parse JSON-encoded list params sent by the
    exploit agent client so reasoning_log/tools_used actually persist."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.patch(
            "/api/v1/agent-sessions/s1",
            params={
                "status": "completed",
                "iteration_count": 1,
                "tools_used": json.dumps(["run_nuclei_scan"]),
                "reasoning_log": json.dumps(["line1", "line2"]),
            },
        )
    assert response.status_code == 200
    call = override_repo.update_agent_session_status.call_args
    assert call.args[3] == ["run_nuclei_scan"]
    assert call.args[5] == ["line1", "line2"]

@pytest.mark.asyncio
async def test_update_agent_session_no_lists(override_repo):
    """Lists omitted entirely must be passed as None (not crash, not empty)."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.patch(
            "/api/v1/agent-sessions/s1",
            params={"status": "completed"},
        )
    assert response.status_code == 200
    call = override_repo.update_agent_session_status.call_args
    assert call.args[3] is None
    assert call.args[5] is None

@pytest.mark.asyncio
async def test_update_agent_session_comma_fallback(override_repo):
    """Comma-separated values are parsed as a fallback for robustness."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.patch(
            "/api/v1/agent-sessions/s1",
            params={
                "status": "completed",
                "reasoning_log": "line1,line2",
            },
        )
    assert response.status_code == 200
    call = override_repo.update_agent_session_status.call_args
    assert call.args[5] == ["line1", "line2"]

@pytest.mark.asyncio
async def test_create_agent_session_parses_json_list_params(override_repo):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/agent-sessions",
            params={
                "session_id": "s1",
                "program_id": "p1",
                "status": "running",
                "tools_used": json.dumps([]),
                "reasoning_log": json.dumps(["step1"]),
            },
        )
    assert response.status_code == 200
    call = override_repo.create_agent_session.call_args
    assert call.args[4] == []
    assert call.args[5] == ["step1"]

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
