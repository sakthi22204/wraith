import pytest
from unittest.mock import AsyncMock, MagicMock
from app.repository import Neo4jRepository
import neo4j.exceptions

@pytest.mark.asyncio
async def test_list_programs_retry_on_transient_error():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Mock result
    mock_result = AsyncMock()

    class MockRecord:
        def __init__(self, data):
            self.data = data
        def __getitem__(self, key):
            return self.data[key]

    mock_records = [
        MockRecord({"p": {"id": "p1", "name": "n1", "platform": "h1", "scope_domains": [], "created_at": "2023-01-01T00:00:00"}})
    ]

    # First call raises TransientError, second succeeds
    mock_session.run.side_effect = [
        neo4j.exceptions.TransientError("Neo.TransientError.Transaction.Outdated", "Conflict"),
        mock_result
    ]

    mock_result.__aiter__.return_value = mock_records

    programs = await repo.list_programs()

    assert len(programs) == 1
    assert programs[0].id == "p1"
    assert mock_session.run.call_count == 2
