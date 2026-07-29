import pytest
import httpx
from httpx import AsyncClient
from unittest.mock import AsyncMock, patch, MagicMock
from app.main import app
from app.api.routes import get_repo
from app.schema import Investigation, Program

# Mock repository class
class MockNeo4jRepository:
    def __init__(self):
        self.create_investigation = AsyncMock()
        self.get_investigation = AsyncMock()
        self.list_investigations = AsyncMock()
        self.delete_investigation_recursive = AsyncMock()
        self.create_program = AsyncMock()
        self.get_program = AsyncMock()
        self.list_programs = AsyncMock()

@pytest.mark.asyncio
@patch("app.api.routes.httpx.AsyncClient")
async def test_create_investigation_mocked(mock_httpx_client):
    # Mock recon orchestrator start endpoint call
    mock_response = MagicMock()
    mock_response.status_code = 202
    mock_response.json.return_value = {"session_id": "session-123"}

    mock_client_instance = AsyncMock()
    mock_client_instance.__aenter__.return_value.post.return_value = mock_response
    mock_client_instance.__aexit__.return_value = False
    mock_httpx_client.return_value = mock_client_instance

    mock_repo = MockNeo4jRepository()
    mock_repo.create_investigation.return_value = Investigation(
        id="test-id",
        name="Test Investigation",
        target="target.local",
        scope_domains=["target.local"],
        created_at="2026-07-29T12:00:00"
    )

    app.dependency_overrides[get_repo] = lambda: mock_repo

    transport = httpx.ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post("/api/v1/investigations", json={
            "name": "Test Investigation",
            "target": "target.local"
        })

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "test-id"
    assert data["name"] == "Test Investigation"
    assert data["target"] == "target.local"
    assert data["scope_domains"] == ["target.local"]
    assert data["program_id"] == "test-id"
    assert data["platform"] == "automatic"

    # Verify repo was called with correct data
    mock_repo.create_investigation.assert_called_once()
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_list_and_get_investigations_mocked():
    mock_repo = MockNeo4jRepository()
    mock_repo.list_investigations.return_value = [
        Investigation(
            id="test-id",
            name="Test Investigation",
            target="target.local",
            scope_domains=["target.local"],
            created_at="2026-07-29T12:00:00"
        )
    ]
    mock_repo.get_investigation.return_value = Investigation(
        id="test-id",
        name="Test Investigation",
        target="target.local",
        scope_domains=["target.local"],
        created_at="2026-07-29T12:00:00"
    )

    app.dependency_overrides[get_repo] = lambda: mock_repo

    transport = httpx.ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        list_resp = await ac.get("/api/v1/investigations")
        get_resp = await ac.get("/api/v1/investigations/test-id")

    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["id"] == "test-id"

    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == "test-id"

    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_legacy_program_routes_mocked():
    mock_repo = MockNeo4jRepository()
    mock_repo.create_program.return_value = Program(
        id="test-id",
        name="Test Program",
        platform="automatic",
        scope_domains=["target.local"],
        created_at="2026-07-29T12:00:00"
    )
    mock_repo.get_program.return_value = Program(
        id="test-id",
        name="Test Program",
        platform="automatic",
        scope_domains=["target.local"],
        created_at="2026-07-29T12:00:00"
    )

    app.dependency_overrides[get_repo] = lambda: mock_repo

    transport = httpx.ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        create_resp = await ac.post("/api/v1/programs", json={
            "name": "Test Program",
            "platform": "HackerOne",
            "scope_domains": ["target.local"]
        })
        get_resp = await ac.get("/api/v1/programs/test-id")

    assert create_resp.status_code == 200
    assert create_resp.json()["id"] == "test-id"

    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == "test-id"

    app.dependency_overrides.clear()
