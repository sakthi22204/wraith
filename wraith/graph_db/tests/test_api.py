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


@pytest.mark.asyncio(loop_scope="session")
async def test_review_can_only_refute_never_confirm(neo4j_driver):
    """There is no human confirmation phase: a review may only refute.

    A "confirmed" decision is refused at the route, so no path exists that can
    mint HUMAN_CONFIRMED and let an unexecuted guess into a report.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        prog_id = (await ac.post(
            "/api/v1/programs",
            json={"name": "Review Check", "platform": "Local", "scope_domains": ["local.host"]},
            headers=_auth(),
        )).json()["id"]
        host_id = (await ac.post(
            f"/api/v1/programs/{prog_id}/hosts", json={"value": "127.0.0.1"},
            headers=_auth(),
        )).json()["id"]
        ep_id = (await ac.post(
            f"/api/v1/hosts/{host_id}/endpoints", json={"url": "/api", "method": "GET"},
            headers=_auth(),
        )).json()["id"]
        finding_id = (await ac.post(
            "/api/v1/findings",
            json={
                "vuln_type": "Information Exposure",
                "severity": "low",
                "confidence": "certain",
                "status": "UNCONFIRMED",
                "description": "Exposed server header",
                "target_id": ep_id,
                "target_type": "endpoint",
            },
            headers=_auth(),
        )).json()["id"]

        confirmed = await ac.post(
            f"/api/v1/findings/{finding_id}/review",
            json={"decision": "confirmed", "note": "looks real"},
            headers=_auth(),
        )
        assert confirmed.status_code == 400, confirmed.text
        assert "no human confirmation" in confirmed.text

        refuted = await ac.post(
            f"/api/v1/findings/{finding_id}/review",
            json={"decision": "false_positive", "note": "sanitized"},
            headers=_auth(),
        )
        assert refuted.status_code == 200, refuted.text
        assert refuted.json()["status"] == "FALSE_POSITIVE"


@pytest.mark.asyncio(loop_scope="session")
async def test_validated_status_needs_two_evidence_sources(neo4j_driver):
    """The three-source rule, end to end through the write path.

    A claim backed only by the agent's own probe (P) is downgraded; the same
    claim with the executed exploit alongside it (P+E) is kept.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        prog_id = (await ac.post(
            "/api/v1/programs",
            json={"name": "Sources Check", "platform": "Local", "scope_domains": ["local.host"]},
            headers=_auth(),
        )).json()["id"]
        host_id = (await ac.post(
            f"/api/v1/programs/{prog_id}/hosts", json={"value": "127.0.0.1"},
            headers=_auth(),
        )).json()["id"]
        ep_id = (await ac.post(
            f"/api/v1/hosts/{host_id}/endpoints", json={"url": "/api", "method": "GET"},
            headers=_auth(),
        )).json()["id"]

        proof = {
            "vuln_type": "SQL Injection",
            "severity": "high",
            "confidence": "high",
            "description": "d",
            "target_id": ep_id,
            "target_type": "endpoint",
            "status": "AI_VALIDATED",
            "poc_request": "GET /?q=1'",
            "poc_response": "HTTP/1.1 500",
            "expected_result": "error",
            "actual_result": "error",
            "validation_stage": "CONDITION_CONFIRMED",
        }

        p_only = await ac.post(
            "/api/v1/findings", json={**proof, "evidence_sources": ["agent_probe"]},
            headers=_auth(),
        )
        assert p_only.status_code == 200, p_only.text
        assert p_only.json()["status"] == "UNCONFIRMED"

        p_plus_e = await ac.post(
            "/api/v1/findings",
            json={**proof, "evidence_sources": ["agent_probe", "exploitation"]},
            headers=_auth(),
        )
        assert p_plus_e.status_code == 200, p_plus_e.text
        assert p_plus_e.json()["status"] == "AI_VALIDATED"


@pytest.mark.asyncio(loop_scope="session")
async def test_observation_can_only_be_promoted_by_corroboration(neo4j_driver):
    """An observation is capped at its own status until a second source agrees."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        prog_id = (await ac.post(
            "/api/v1/programs",
            json={"name": "Observation Check", "platform": "Local", "scope_domains": ["local.host"]},
            headers=_auth(),
        )).json()["id"]
        host_id = (await ac.post(
            f"/api/v1/programs/{prog_id}/hosts", json={"value": "127.0.0.1"},
            headers=_auth(),
        )).json()["id"]
        ep_id = (await ac.post(
            f"/api/v1/hosts/{host_id}/endpoints", json={"url": "/login", "method": "POST"},
            headers=_auth(),
        )).json()["id"]

        created = await ac.post(
            "/api/v1/findings",
            json={
                "vuln_type": "Missing Rate Limiting",
                "severity": "medium",
                "confidence": "medium",
                "description": "no lockout after repeated logins",
                "target_id": ep_id,
                "target_type": "endpoint",
                "status": "OBSERVATION",
                "poc_request": "POST /login x20",
                "poc_response": "all attempts answered, no throttling",
                "evidence_sources": ["agent_probe", "exploitation"],
            },
            headers=_auth(),
        )
        assert created.status_code == 200, created.text
        finding = created.json()
        assert finding["status"] == "OBSERVATION"
        # A negative signal is never stored above the middle of the scale.
        assert finding["severity"] in {"low", "medium"}

        fid = finding["id"]
        await ac.post(f"/api/v1/findings/{fid}/corroborate",
                      json={"source_name": "external-scanner"}, headers=_auth())
        promoted = await ac.post(f"/api/v1/findings/{fid}/corroborate",
                                 json={"source_name": "manual-review"}, headers=_auth())
        assert promoted.status_code == 200, promoted.text
        assert promoted.json()["status"] == "CORROBORATED"