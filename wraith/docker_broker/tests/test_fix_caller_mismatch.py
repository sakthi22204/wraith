import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings

@pytest.mark.asyncio
async def test_create_container_no_caller_field():
    """Verify that container creation works without a 'caller' field in the body,
    as it's now derived from the bearer token."""
    headers = {"Authorization": f"Bearer {settings.RECON_BROKER_TOKEN}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        spec = {
            "image": "projectdiscovery/subfinder:latest",
            "command": ["-h"],
            "detach": True
        }

        from unittest.mock import patch
        with patch("app.api.routes.docker_proxy.create_container") as mock_create:
            mock_create.return_value = "test_container_id"
            response = await ac.post("/api/v1/containers", json=spec, headers=headers)

        assert response.status_code == 200
        assert response.json()["container_id"] == "test_container_id"

        # Verify ownership was tracked correctly with identity from token
        from app.api.routes import container_ownership
        assert container_ownership["test_container_id"] == "recon_orchestrator"
