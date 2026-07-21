import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings
from app.proxy import docker_proxy

@pytest.mark.asyncio
async def test_create_container_regression_caller_prop():
    """
    Ensure that passing 'caller' in the spec dict does not cause
    TypeError when invoking self.client.containers.run in proxy.py.
    """
    # 1. Setup mock Docker client on the real proxy
    mock_container = MagicMock()
    mock_container.id = "regression-test-container-id"

    mock_client = MagicMock()
    mock_client.containers.run.return_value = mock_container

    # Store old client and set mock client
    old_client = docker_proxy._client
    docker_proxy._client = mock_client

    try:
        # 2. Setup standard auth header
        headers = {"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}

        # 3. Create request spec containing a 'caller' key
        spec = {
            "image": "projectdiscovery/subfinder:latest",
            "command": ["-h"],
            "caller": "recon_orchestrator"
        }

        # Mock the validator to avoid having to fully satisfy whitelist rules in this test if not needed,
        # but let's see if we can let it run normally. The image is on the whitelist.
        with patch("app.proxy.validate_container_spec"):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                response = await ac.post("/api/v1/containers", json=spec, headers=headers)

        # 4. Assert response was 200 OK
        assert response.status_code == 200
        assert response.json()["container_id"] == "regression-test-container-id"

        # 5. Assert containers.run was called, and specifically that 'caller' is NOT in the keyword arguments
        assert mock_client.containers.run.called
        called_kwargs = mock_client.containers.run.call_args[1]
        assert "caller" not in called_kwargs

    finally:
        # Restore the old client state
        docker_proxy._client = old_client
