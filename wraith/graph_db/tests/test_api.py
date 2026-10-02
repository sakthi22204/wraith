"""End-to-end HTTP test of the route layer against a real Neo4j.

This module was excluded from the test runs and, separately, broken: the async
fixtures above lacked pytest_asyncio decorators, and `AsyncClient(app=app)` was
removed in httpx 0.28. Both are fixed here, because this is the only test that
exercises the routes rather than the repository -- which is exactly the layer
where the missing auth guards lived.

Note which calls carry a token. `POST /api/v1/findings` is token-guarded, and the
guarded routes are asserted separately and exhaustively in test_write_auth.py.
Here the point is that the guarded write still works for an authenticated caller,
so a missing guard and a broken write cannot be confused for each other.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config import settings


TOKEN = "admin-token-fixed-for-this-test"


@pytest.fixture(autouse=True)
def configured_token(monkeypatch):
    monkeypatch.setattr("app.auth.settings.ADMIN_API_TOKEN", TOKEN)


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


@pytest.mark.asyncio(loop_scope="session")
async def test_health_endpoint(neo4j_driver):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio(loop_scope="session")
async def test_full_flow(neo4j_driver):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create Program
        prog_res = await ac.post(
            "/api/v1/programs",
            json={
                "name": "Integration Test",
                "platform": "Local",
                "scope_domains": ["local.host"],
            },
            headers=_auth(),
        )
        assert prog_res.status_code == 200, prog_res.text
        prog_id = prog_res.json()["id"]

        # 2. Add Host
        host_res = await ac.post(
            f"/api/v1/programs/{prog_id}/hosts", json={"value": "127.0.0.1"},
            headers=_auth(),
        )
        assert host_res.status_code == 200, host_res.text
        host_id = host_res.json()["id"]

        # 3. Add Finding (token-guarded since Phase 1)
        ep_res = await ac.post(
            f"/api/v1/hosts/{host_id}/endpoints",
            json={"url": "/api", "method": "GET"},
            headers=_auth(),
        )
        ep_id = ep_res.json()["id"]

        finding_res = await ac.post(
            "/api/v1/findings",
            json={
                "vuln_type": "Information Exposure",
                "severity": "low",
                "confidence": "certain",
                # Was "triaged", which is not a FindingStatus member and has not
                # been for some time -- part of why this module rotted unnoticed.
                # A newly discovered finding starts UNCONFIRMED.
                "status": "UNCONFIRMED",
                "description": "Exposed server header",
                "target_id": ep_id,
                "target_type": "endpoint",
            },
            headers=_auth(),
        )
        assert finding_res.status_code == 200, finding_res.text

        # 4. Get Graph
        graph_res = await ac.get(f"/api/v1/programs/{prog_id}/graph")
        assert graph_res.status_code == 200
        data = graph_res.json()
        assert "nodes" in data
        assert "links" in data
        assert len(data["nodes"]) >= 4


@pytest.mark.asyncio(loop_scope="session")
async def test_the_finding_write_really_is_guarded_end_to_end(neo4j_driver):
    """The same call as above, without the token, against a live database.

    test_write_auth.py proves this with a mocked repository; this proves the
    route does not reach Neo4j at all. Together they rule out a guard that
    answers 401 after the write has already landed.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        prog_res = await ac.post(
            "/api/v1/programs",
            json={
                "name": "Guard Check",
                "platform": "Local",
                "scope_domains": ["local.host"],
            },
            headers=_auth(),
        )
        prog_id = prog_res.json()["id"]
        host_res = await ac.post(
            f"/api/v1/programs/{prog_id}/hosts", json={"value": "guard.example"},
            headers=_auth(),
        )
        host_id = host_res.json()["id"]
        ep_res = await ac.post(
            f"/api/v1/hosts/{host_id}/endpoints",
            json={"url": "/api", "method": "GET"},
            headers=_auth(),
        )
        ep_id = ep_res.json()["id"]

        anonymous = await ac.post(
            "/api/v1/findings",
            json={
                "vuln_type": "SQL Injection",
                "severity": "critical",
                "confidence": "high",
                "status": "HUMAN_CONFIRMED",
                "description": "Anonymous forgery attempt",
                "target_id": ep_id,
                "target_type": "endpoint",
                "validation_stage": "EXECUTED",
                "poc_request": "GET /?q=1' OR '1'='1",
                "poc_response": "HTTP/1.1 200 OK",
                "expected_result": "dumped",
                "actual_result": "dumped",
            },
        )
        assert anonymous.status_code == 401, anonymous.text

        # Nothing was written: the finding count is unchanged.
        findings = await ac.get(f"/api/v1/investigations/{prog_id}/findings")
        assert findings.json() == []