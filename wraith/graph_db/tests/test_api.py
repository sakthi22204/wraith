import pytest
from httpx import AsyncClient
from app.main import app
from app.repository import Neo4jRepository
from app.client import neo4j_client

@pytest.mark.asyncio
async def test_health_endpoint(neo4j_driver):
    # Ensure app is using the test driver/settings
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_full_flow(neo4j_driver):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        # 1. Create Program
        prog_res = await ac.post("/api/v1/programs", json={
            "name": "Integration Test",
            "platform": "Local",
            "scope_domains": ["local.host"]
        })
        assert prog_res.status_code == 200
        prog_id = prog_res.json()["id"]

        # 2. Add Host
        host_res = await ac.post(f"/api/v1/programs/{prog_id}/hosts", json={"value": "127.0.0.1"})
        assert host_res.status_code == 200
        host_id = host_res.json()["id"]

        # 3. Add Finding
        # First need an endpoint
        ep_res = await ac.post(f"/api/v1/hosts/{host_id}/endpoints", json={"url": "/api", "method": "GET"})
        ep_id = ep_res.json()["id"]

        finding_res = await ac.post("/api/v1/findings", json={
            "vuln_type": "Information Exposure",
            "severity": "low",
            "confidence": "certain",
            "status": "triaged",
            "description": "Exposed server header",
            "target_id": ep_id,
            "target_type": "endpoint"
        })
        assert finding_res.status_code == 200

        # 4. Get Graph
        graph_res = await ac.get(f"/api/v1/programs/{prog_id}/graph")
        assert graph_res.status_code == 200
        data = graph_res.json()
        assert "nodes" in data
        assert "links" in data
        assert len(data["nodes"]) >= 4
