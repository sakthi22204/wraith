import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_docker_client():
    with patch("docker.DockerClient") as mock:
        yield mock

@pytest.mark.asyncio
async def test_spawn_container_cleanup(mock_docker_client):
    from app.docker_spawner import DockerSpawner

    mock_container = MagicMock()
    mock_container.wait.return_value = {"StatusCode": 0}
    mock_container.logs.return_value = b"test output"

    mock_docker_client.return_value.containers.run.return_value = mock_container

    spawner = DockerSpawner()

    output = await spawner.spawn_container("test-image", ["cmd"])

    assert output == "test output"
    mock_container.stop.assert_called_once()
    mock_container.remove.assert_called_once()
