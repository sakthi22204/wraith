import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import settings
from unittest.mock import patch, MagicMock

client = TestClient(app)

@pytest.fixture
def mock_docker():
    # Patch the _client attribute directly to avoid property setter issues
    with patch("app.proxy.docker_proxy._client") as mock:
        # Also ensure we don't try to create a real client
        with patch("docker.DockerClient") as mock_class:
             yield mock

def test_ownership_isolation(mock_docker):
    # Mock docker container
    mock_container = MagicMock()
    mock_container.id = "container-123"
    mock_docker.containers.run.return_value = mock_container
    mock_docker.containers.get.return_value = mock_container

    # 1. Create container as Service A (Recon Orchestrator)
    headers_a = {"Authorization": f"Bearer {settings.RECON_ORCHESTRATOR_TOKEN}"}
    resp = client.post("/api/v1/containers", json={"image": "projectdiscovery/subfinder:latest", "command": ["-d", "example.com"]}, headers=headers_a)
    assert resp.status_code == 200
    container_id = resp.json()["container_id"]

    # 2. Try to get logs as Service B (Active Exploit Runner) - should fail 403
    headers_b = {"Authorization": f"Bearer {settings.ACTIVE_EXPLOIT_RUNNER_TOKEN}"}
    resp = client.get(f"/api/v1/containers/{container_id}/logs", headers=headers_b)
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Not authorized to access this container"

    # 3. Try to stop as Service B - should fail 403
    resp = client.post(f"/api/v1/containers/{container_id}/stop", headers=headers_b)
    assert resp.status_code == 403

    # 4. Try to stop as Service B even if passing caller query param - should still fail 403 (because param is ignored now)
    resp = client.post(f"/api/v1/containers/{container_id}/stop", params={"caller": "recon_orchestrator"}, headers=headers_b)
    assert resp.status_code == 403

    # 5. Get logs as Service A - should succeed
    mock_container.logs.return_value = b"some logs"
    resp = client.get(f"/api/v1/containers/{container_id}/logs", headers=headers_a)
    assert resp.status_code == 200
    assert resp.json()["logs"] == "some logs"

    # 6. Stop as Service A - should succeed
    resp = client.post(f"/api/v1/containers/{container_id}/stop", headers=headers_a)
    assert resp.status_code == 200
    assert resp.json()["status"] == "stopped"
