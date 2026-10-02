import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings

@pytest.mark.asyncio
async def test_create_container_allowed():
    mock_container = MagicMock()
    mock_container.id = "test-id"

    with patch("app.proxy.docker.DockerClient") as mock_docker:
        mock_docker.from_env.return_value.containers.run.return_value = mock_container
        # Setup for our proxy class which uses DockerClient(base_url=...)
        mock_docker.return_value.containers.run.return_value = mock_container

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/containers",
                json={
                    "image": "projectdiscovery/subfinder:latest",
                    "command": ["-d", "example.com"]
                },
                headers={"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
            )

    assert response.status_code == 200
    assert response.json()["container_id"] == "test-id"

@pytest.mark.asyncio
async def test_create_container_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/containers",
            json={
                "image": "malicious/image:latest"
            },
            headers={"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
        )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_only_allowlisted_kwargs_reach_the_docker_sdk():
    """End-to-end: whatever the validator lets past is exactly what the SDK is
    called with.

    The validator alone is not the boundary -- proxy.py used to forward
    **spec, so any key the validator failed to name still reached
    containers.run. This asserts the call site, not just the validator.
    """
    mock_container = MagicMock()
    mock_container.id = "test-id"

    with patch("app.proxy.docker.DockerClient") as mock_docker:
        mock_docker.return_value.containers.run.return_value = mock_container
        mock_docker.return_value.images.get.return_value = MagicMock()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/containers",
                json={
                    "image": "projectdiscovery/subfinder:latest",
                    "command": ["-d", "example.com"],
                    "mem_limit": "512m",
                    "network": settings.RECON_DOCKER_NETWORK,
                    "detach": True,
                    "remove": False,
                },
                headers={"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
            )

    assert response.status_code == 200
    _, kwargs = mock_docker.return_value.containers.run.call_args
    assert set(kwargs) <= {
        "image", "command", "mem_limit", "cpu_quota", "network", "detach",
        "remove", "volumes", "extra_hosts", "environment",
    }
    assert kwargs["mem_limit"] == "512m"


@pytest.mark.asyncio
async def test_host_bind_mount_never_reaches_the_docker_sdk():
    """The exact exploit: the request is refused and run() is never called."""
    mock_container = MagicMock()
    mock_container.id = "test-id"

    with patch("app.proxy.docker.DockerClient") as mock_docker:
        mock_docker.return_value.containers.run.return_value = mock_container
        mock_docker.return_value.images.get.return_value = MagicMock()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            response = await ac.post(
                "/api/v1/containers",
                json={
                    "image": "projectdiscovery/httpx:latest",
                    "command": ["-u", "https://example.com"],
                    "mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}],
                },
                headers={"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
            )

    assert response.status_code == 403
    mock_docker.return_value.containers.run.assert_not_called()
