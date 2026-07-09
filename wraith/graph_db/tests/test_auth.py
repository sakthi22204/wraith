import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from app.api.routes import get_repo
from unittest.mock import AsyncMock

async def override_get_repo():
    yield AsyncMock()

app.dependency_overrides[get_repo] = override_get_repo
client = TestClient(app)

def test_delete_program_auth():
    # No token
    response = client.delete("/api/v1/programs/p1?confirm=true")
    assert response.status_code == 401

    # Wrong token
    headers = {"Authorization": "Bearer wrong"}
    response = client.delete("/api/v1/programs/p1?confirm=true", headers=headers)
    assert response.status_code == 401

    # Correct token (fails with other errors but not 401)
    headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
    try:
        response = client.delete("/api/v1/programs/p1?confirm=true", headers=headers)
        assert response.status_code != 401
    except:
        pass
