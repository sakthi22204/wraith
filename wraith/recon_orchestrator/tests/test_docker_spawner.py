import pytest
from unittest.mock import AsyncMock, patch
from httpx import Response, Request

@pytest.mark.asyncio
async def test_spawn_container_success():
    from app.docker_spawner import DockerSpawner

    spawner = DockerSpawner(broker_url="http://broker")

    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value

        # 1. Mock create response
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request), # create
            Response(200, json={"StatusCode": 0}, request=dummy_request)             # wait
        ]
        # 2. Mock logs response
        mock_ac.get.return_value = Response(200, json={"logs": "test-output"}, request=dummy_request)
        # 3. Mock delete response
        mock_ac.delete.return_value = Response(200, request=dummy_request)

        output = await spawner.spawn_container("test-image", ["cmd"])

        assert output == "test-output"

        # Verify calls
        assert mock_ac.post.call_count == 2
        assert mock_ac.get.called
        assert mock_ac.delete.called

@pytest.mark.asyncio
async def test_spawn_container_cleanup_on_failure():
    from app.docker_spawner import DockerSpawner

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value

        # 1. Mock create response success
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(500, request=dummy_request) # wait fails
        ]

        mock_ac.delete.return_value = Response(200, request=dummy_request)

        with pytest.raises(Exception):
            await spawner.spawn_container("test-image", ["cmd"])

        # Cleanup should still be called
        assert mock_ac.delete.called
