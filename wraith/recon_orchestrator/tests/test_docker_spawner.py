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

@pytest.mark.asyncio
async def test_spawn_container_cleanup_logging_on_http_error():
    from app.docker_spawner import DockerSpawner
    import httpx

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value

        # Mock create/wait success, logs success, delete raising HTTPError
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(200, json={"StatusCode": 0}, request=dummy_request)
        ]
        mock_ac.get.return_value = Response(200, json={"logs": "test-output"}, request=dummy_request)

        # Raise HTTPError on cleanup
        mock_ac.delete.side_effect = httpx.HTTPError("cleanup connection error")

        with patch("app.docker_spawner.logger.warning") as mock_warn:
            output = await spawner.spawn_container("test-image", ["cmd"])

            assert output == "test-output" # should still return output (best effort cleanup)
            # Cleanup is retried 3 times, then a final warning reports the orphan.
            assert mock_warn.call_count == 4
            assert any("Failed to cleanup container" in args[0][0] for args in mock_warn.call_args_list)
            assert mock_warn.call_args_list[-1][0][0] == "Container 'test-id' was NOT cleaned up after 3 attempts."


@pytest.mark.asyncio
async def test_spawn_container_cleanup_retries_then_succeeds():
    from app.docker_spawner import DockerSpawner
    import httpx

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value

        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(200, json={"StatusCode": 0}, request=dummy_request)
        ]
        mock_ac.get.return_value = Response(200, json={"logs": "test-output"}, request=dummy_request)

        # Cleanup fails twice then succeeds
        mock_ac.delete.side_effect = [httpx.HTTPError("first"), httpx.HTTPError("second"), Response(200, request=dummy_request)]

        with patch("app.docker_spawner.logger.warning") as mock_warn:
            output = await spawner.spawn_container("test-image", ["cmd"])

            assert output == "test-output"
            assert mock_ac.delete.call_count == 3
            assert mock_warn.call_count == 2


# -- an aborted pass must surface, carrying what it produced -------------------
#
# The broker stops a container at its deadline (or the runtime OOM-kills it)
# and the spawner used to hand back its logs as an ordinary success. The caller
# could not tell a completed scan from one that was cut off, so a deadline-
# stopped pass was retried against the budget that had just refused it, and its
# partial findings were reported as if the run had finished cleanly.


@pytest.mark.asyncio
async def test_deadline_abort_raises_with_the_partial_logs():
    from app.docker_spawner import DockerSpawner, ToolDeadlineReached

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(200, json={"StatusCode": -1, "TimedOut": True,
                                "Error": {"Message": "budget exceeded"}},
                      request=dummy_request),
        ]
        mock_ac.get.return_value = Response(
            200, json={"logs": '{"matched-at":"http://target/"}'},
            request=dummy_request)
        mock_ac.delete.return_value = Response(200, request=dummy_request)

        with pytest.raises(ToolDeadlineReached) as exc:
            await spawner.spawn_container("test-image", ["cmd"], timeout=60)

        # The partial output rides along; without it a stopped scan reports
        # "0 findings" for work it actually did.
        assert 'matched-at' in exc.value.logs
        # Cleanup still ran: an aborted container is exactly the one that
        # would otherwise be left behind.
        assert mock_ac.delete.called


@pytest.mark.asyncio
async def test_oom_kill_raises_and_is_not_a_success():
    from app.docker_spawner import DockerSpawner, ToolOOMKilled

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(200, json={"StatusCode": 137, "OOMKilled": True,
                                "Error": {"Message": "OOM killed"}},
                      request=dummy_request),
        ]
        mock_ac.get.return_value = Response(200, json={"logs": "partial"}, request=dummy_request)
        mock_ac.delete.return_value = Response(200, request=dummy_request)

        with pytest.raises(ToolOOMKilled) as exc:
            await spawner.spawn_container("test-image", ["cmd"])

        assert exc.value.logs == "partial"
        assert mock_ac.delete.called


@pytest.mark.asyncio
async def test_a_successful_wait_is_still_just_logs():
    """The success path stays a plain string: every caller that mocks the
    spawner returns one, and the flags arrive only through the abort path."""
    from app.docker_spawner import DockerSpawner

    spawner = DockerSpawner(broker_url="http://broker")
    dummy_request = Request("POST", "http://broker")

    with patch("httpx.AsyncClient") as mock_client:
        mock_ac = mock_client.return_value.__aenter__.return_value
        mock_ac.post.side_effect = [
            Response(200, json={"container_id": "test-id"}, request=dummy_request),
            Response(200, json={"StatusCode": 1, "TimedOut": False,
                                "OOMKilled": False}, request=dummy_request),
        ]
        mock_ac.get.return_value = Response(200, json={"logs": "out"}, request=dummy_request)
        mock_ac.delete.return_value = Response(200, request=dummy_request)

        # A non-zero exit is the tool's own verdict (an empty probe, a strict
        # linter), not an abort: it is not our place to reinterpret it.
        assert await spawner.spawn_container("test-image", ["cmd"]) == "out"
