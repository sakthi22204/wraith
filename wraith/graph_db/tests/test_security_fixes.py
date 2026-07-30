import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock
from app.repository import Neo4jRepository
from app.schema import FindingCreate, FindingStatus

@pytest.mark.asyncio
async def test_create_finding_injection_safe():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Attempt injection via target_type
    finding = FindingCreate(
        vuln_type="sqli",
        severity="high",
        confidence="high",
        status=FindingStatus.UNCONFIRMED,
        description="test",
        target_id="123",
        target_type="Endpoint}) DETACH DELETE t //"
    )

    with pytest.raises(ValueError) as exc:
        await repo.create_finding(finding)
    assert "Invalid target_type" in str(exc.value)

    # Verify no query was run on the session when it failed validation
    assert mock_session.run.call_count == 0

@pytest.mark.asyncio
async def test_create_finding_valid_types():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Test Endpoint
    finding_endpoint = FindingCreate(
        vuln_type="sqli",
        severity="high",
        confidence="high",
        status=FindingStatus.UNCONFIRMED,
        description="test",
        target_id="123",
        target_type="endpoint"
    )

    # Mock result
    mock_result = AsyncMock()
    mock_record = MagicMock()
    # Need to mock the returned finding object. The repository returns Finding(**record["f"])
    mock_record.__getitem__.return_value = {
        "id": "f1",
        "vuln_type": "sqli",
        "severity": "high",
        "confidence": "high",
        "status": "UNCONFIRMED",
        "description": "test",
        "discovered_at": datetime.utcnow().isoformat() + "Z"
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    await repo.create_finding(finding_endpoint)

    # Check that it matched the correct query pattern (static)
    args, kwargs = mock_session.run.call_args
    query = args[0]
    assert "MATCH (t:Endpoint {id: $target_id})" in query

    # Test Parameter
    finding_parameter = FindingCreate(
        vuln_type="sqli",
        severity="high",
        confidence="high",
        status=FindingStatus.UNCONFIRMED,
        description="test",
        target_id="123",
        target_type="parameter"
    )

    await repo.create_finding(finding_parameter)
    args, kwargs = mock_session.run.call_args
    query = args[0]
    assert "MATCH (t:Parameter {id: $target_id})" in query

@pytest.mark.asyncio
async def test_get_program():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Mock found
    mock_result = AsyncMock()
    mock_record = MagicMock()
    mock_record.__getitem__.return_value = {
        "id": "p1",
        "name": "test",
        "target": "example.com",
        "scope_domains": ["example.com"],
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }
    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    program = await repo.get_program("p1")
    assert program.id == "p1"
    assert program.scope_domains == ["example.com"]

    # Mock not found
    mock_result_empty = AsyncMock()
    mock_result_empty.single.return_value = None
    mock_session.run.return_value = mock_result_empty

    program = await repo.get_program("p2")
    assert program is None

@pytest.mark.asyncio
async def test_list_programs():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Mock result with 2 programs
    mock_result = AsyncMock()

    class MockRecord:
        def __init__(self, data):
            self.data = data
        def __getitem__(self, key):
            return self.data[key]

    mock_records = [
        MockRecord({"i": {"id": "p1", "name": "n1", "target": "example.com", "status": "active", "created_at": datetime.utcnow().isoformat()}}),
        MockRecord({"i": {"id": "p2", "name": "n2", "target": "example2.com", "status": "active", "created_at": datetime.utcnow().isoformat()}})
    ]

    mock_result.__aiter__.return_value = mock_records
    mock_session.run.return_value = mock_result

    programs = await repo.list_programs()
    assert len(programs) == 2
    assert programs[0].id == "p1"
    assert programs[1].id == "p2"

@pytest.mark.asyncio
async def test_get_attack_surface():
    mock_session = AsyncMock()
    repo = Neo4jRepository(mock_session)

    # Mock result
    mock_result = AsyncMock()

    class MockNode:
        def __init__(self, id, labels, props):
            self.id = id
            self.labels = set(labels)
            self.props = props
        def __getitem__(self, key):
            return self.props[key]
        def __iter__(self):
            return iter(self.props)
        def items(self):
            return self.props.items()

    class MockRel:
        def __init__(self, start_id, end_id, type):
            self.start_node = {"id": start_id}
            self.end_node = {"id": end_id}
            self.type = type

    mock_record = {
        "nodes": [
            MockNode("p1", ["Program"], {"id": "p1", "name": "prog1"}),
            MockNode("h1", ["Host"], {"id": "h1", "value": "1.2.3.4"})
        ],
        "relationships": [
            MockRel("p1", "h1", "IN_SCOPE")
        ]
    }

    mock_result.single.return_value = mock_record
    mock_session.run.return_value = mock_result

    surface = await repo.get_attack_surface("p1")

    # Verify query
    args, kwargs = mock_session.run.call_args
    query = args[0]
    assert "apoc.path.subgraphAll" in query

    # Verify processing
    assert len(surface["nodes"]) == 2
    assert len(surface["links"]) == 1
    assert surface["nodes"][0]["id"] == "p1"
    assert surface["links"][0]["source"] == "p1"
    assert surface["links"][0]["type"] == "IN_SCOPE"
