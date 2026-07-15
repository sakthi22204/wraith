import pytest
import docker
from unittest.mock import MagicMock, patch
from app.proxy import DockerProxy

@pytest.mark.asyncio
async def test_create_container_pulls_if_missing():
    proxy = DockerProxy()
    mock_client = MagicMock()
    proxy._client = mock_client

    spec = {
        "image": "projectdiscovery/subfinder:latest",
        "command": ["-d", "example.com"]
    }

    # Mock image not found initially, then found after pull
    mock_client.images.get.side_effect = [
        docker.errors.ImageNotFound("not found"),
        MagicMock()
    ]

    # Mock containers.run to return a mock container
    mock_container = MagicMock()
    mock_container.id = "test-id"
    mock_client.containers.run.return_value = mock_container

    with patch("app.proxy.validate_container_spec"):
        # We need to mock asyncio.to_thread because it executes the nested 'run' function
        # Or better, just test the 'run' function if it were accessible, but it's not.
        # Since create_container calls asyncio.to_thread(run), we patch to_thread.

        async def mock_to_thread(func, *args, **kwargs):
            return func(*args, **kwargs)

        with patch("asyncio.to_thread", side_effect=mock_to_thread):
            await proxy.create_container(spec.copy())

    assert mock_client.images.pull.called
    assert mock_client.images.pull.call_args[0][0] == "projectdiscovery/subfinder:latest"
    assert mock_client.containers.run.called
