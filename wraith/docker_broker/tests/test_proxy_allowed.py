import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_create_container_allowed():
    mock_container = MagicMock()
    mock_container.id = "test-id"

    with patch("app.proxy.docker.DockerClient") as mock_docker:
        mock_docker.from_env.return_value.containers.run.return_value = mock_container
        # Setup for our proxy class which uses DockerClient(base_url=...)
        mock_docker.return_value.containers.run.return_value = mock_container

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post("/api/v1/containers", json={
                "image": "projectdiscovery/subfinder:latest",
                "command": ["-d", "example.com"]
            })

    assert response.status_code == 200
    assert response.json()["container_id"] == "test-id"

@pytest.mark.asyncio
async def test_create_container_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/containers", json={
            "image": "malicious/image:latest"
        })
    assert response.status_code == 403
