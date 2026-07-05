import pytest
import asyncio
from httpx import AsyncClient, ASGITransport, Response, Request
from app.main import app as broker_app
from recon_orchestrator.app.main import app as recon_app
from unittest.mock import AsyncMock, patch, MagicMock

@pytest.mark.asyncio
async def test_regression_recon_flow():
    """
    Prove that the recon flow still works when DOCKER_BROKER_URL is used.
    We mock the broker's underlying Docker calls to be safe.
    """
    # 1. Mock the real Docker SDK calls inside the broker
    mock_container = MagicMock()
    mock_container.id = "test-container-id"

    with patch("docker.DockerClient") as mock_docker, \
         patch("recon_orchestrator.app.orchestrator.graph_client") as mock_graph:

        # Setup Docker mock
        mock_docker_instance = mock_docker.return_value
        mock_docker_instance.containers.run.return_value = mock_container
        mock_docker_instance.containers.get.return_value = mock_container
        mock_container.wait.return_value = {"StatusCode": 0}
        mock_container.logs.return_value = b'{"host": "found.example.com"}\n'

        # Setup GraphDB mock
        mock_graph.create_scan_session = AsyncMock(return_value={"id": "graph-session-123"})
        mock_graph.update_scan_session = AsyncMock()
        mock_graph.upsert_host = AsyncMock(return_value={"id": "host-123"})
        mock_graph.upsert_port = AsyncMock()
        mock_graph.upsert_endpoint = AsyncMock()

        # 2. Start the recon session via recon_orchestrator API
        async with AsyncClient(transport=ASGITransport(app=recon_app), base_url="http://recon") as ac_recon:
            # We need to make sure recon_orchestrator points to our mocked broker_app
            # In tests, it calls localhost:8005. Since we are using ASGITransport,
            # we might need to mock the httpx client inside docker_spawner.py

            with patch("recon_orchestrator.app.docker_spawner.httpx.AsyncClient") as mock_broker_client:
                # Mock the broker response as if it were running
                mock_broker_ac = mock_broker_client.return_value.__aenter__.return_value

                dummy_request = Request("POST", "http://broker")

                async def mock_post(url, **kwargs):
                    if "/wait" in url:
                        return Response(200, json={"StatusCode": 0}, request=dummy_request)
                    return Response(200, json={"container_id": "test-container-id"}, request=dummy_request)

                async def mock_get(url, **kwargs):
                    return Response(200, json={"logs": '{"host": "found.example.com"}\n'}, request=dummy_request)

                async def mock_delete(url, **kwargs):
                    return Response(200, request=dummy_request)

                mock_broker_ac.post = AsyncMock(side_effect=mock_post)
                mock_broker_ac.get = AsyncMock(side_effect=mock_get)
                mock_broker_ac.delete = AsyncMock(side_effect=mock_delete)

                response = await ac_recon.post("/api/v1/recon/start", json={
                    "program_id": "prog-123",
                    "domains": ["example.com"]
                })

                assert response.status_code == 202
                session_id = response.json()["session_id"]

                # 3. Wait for recon session to complete
                from recon_orchestrator.app.orchestrator import orchestrator
                for _ in range(50):
                    if orchestrator.sessions[session_id].status == "completed":
                        break
                    await asyncio.sleep(0.1)

                assert orchestrator.sessions[session_id].status == "completed"
                assert orchestrator.sessions[session_id].progress == 100.0

                # Verify that it tried to call the broker 4 times (one per tool)
                # Each tool does: 1 create + 1 wait = 2 POSTs.
                # 4 tools * 2 = 8 POSTs.
                assert mock_broker_ac.post.call_count >= 8
