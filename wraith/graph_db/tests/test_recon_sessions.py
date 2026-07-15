import pytest
from unittest.mock import AsyncMock, MagicMock
from app.repository import Neo4jRepository
from app.schema import ReconSession

@pytest.mark.asyncio
async def test_create_recon_session_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = {
        "id": "s1",
        "program_id": "p1",
        "domains": ["example.com"],
        "status": "accepted",
        "started_at": "2023-01-01T00:00:00Z"
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    session = await repo.create_recon_session("s1", "p1", ["example.com"], "accepted")

    assert session.id == "s1"
    assert session.status == "accepted"
    assert mock_session.run.call_count == 1
    args, kwargs = mock_session.run.call_args
    assert "MERGE (s:ReconSession {id: $id})" in args[0]

@pytest.mark.asyncio
async def test_update_recon_session_status_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = {
        "id": "s1",
        "program_id": "p1",
        "domains": ["example.com"],
        "status": "completed",
        "started_at": "2023-01-01T00:00:00Z",
        "completed_at": "2023-01-01T00:05:00Z",
        "tool_results": '{"hosts_found": 1}'
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    session = await repo.update_recon_session_status("s1", "completed", {"hosts_found": 1})

    assert session.status == "completed"
    assert session.tool_results == {"hosts_found": 1}
    assert mock_session.run.call_count == 1
    args, kwargs = mock_session.run.call_args
    assert "SET s.status = $status" in args[0]
    assert "s.completed_at = $now" in args[0]

@pytest.mark.asyncio
async def test_list_recon_sessions_mock():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()

    class MockRecord:
        def __init__(self, data):
            self.data = data
        def __getitem__(self, key):
            return self.data[key]

    mock_records = [
        MockRecord({"s": {"id": "s1", "program_id": "p1", "domains": [], "status": "completed", "started_at": "2023-01-01T00:00:00Z"}})
    ]

    mock_result.__aiter__.return_value = mock_records
    mock_session.run.return_value = mock_result

    sessions = await repo.list_recon_sessions("p1")
    assert len(sessions) == 1
    assert sessions[0].id == "s1"
    assert mock_session.run.call_count == 1

@pytest.mark.asyncio
async def test_update_recon_session_status_not_found():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    mock_result = AsyncMock()
    mock_result.single.return_value = None
    mock_session.run.return_value = mock_result

    with pytest.raises(ValueError) as exc:
        await repo.update_recon_session_status("nonexistent", "completed")
    assert "not found" in str(exc.value)
