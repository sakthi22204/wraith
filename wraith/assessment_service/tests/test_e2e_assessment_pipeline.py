"""
End-to-end test for assessment_service.

GAP THIS FILLS: the only existing test (test_assessment.py) calls
AssessmentEngine.generate_report() directly as a bare function -- no HTTP,
no auth, no graph_db interaction, no caching behavior, no error handling.
The actual FastAPI endpoints (perform_assessment / get_assessment), their
real outbound httpx call to graph_db, and the in-memory cache have never
been exercised.

This test drives the real app via real HTTP, with only graph_db mocked at
the wire level (respx) -- the genuinely external dependency. Routing,
the real httpx call, AssessmentEngine's scoring/correlation/prioritization
logic, and the assessments_db cache all run unmodified.
"""
import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

from app.main import app
from app.config import settings
import app.main as assessment_main

INVESTIGATION_ID = "inv-e2e-1"
GRAPH_URL = f"{settings.GRAPH_DB_URL}/investigations/{INVESTIGATION_ID}/graph"


@pytest.fixture(autouse=True)
def _clear_assessment_cache():
    """assessments_db is a module-level in-memory cache -- clear it between
    tests so one test's cached report can't mask another test's expected
    graph_db call."""
    assessment_main.assessments_db.clear()
    yield
    assessment_main.assessments_db.clear()

RICH_GRAPH = {
    "nodes": [
        {"id": "h1", "labels": ["Host"], "properties": {"value": "shop.example.com"}},
        {"id": "s1", "labels": ["Service"], "properties": {"name": "OpenSSH"}},
        {"id": "s2", "labels": ["Service"], "properties": {"name": "nginx"}},
        {"id": "e1", "labels": ["Endpoint"], "properties": {"url": "/admin/login"}},
        {"id": "e2", "labels": ["Endpoint"], "properties": {"url": "/api/v1/users"}},
        {"id": "e3", "labels": ["Endpoint"], "properties": {"url": "/wp-content/uploads/x.js"}},
        {"id": "f1", "labels": ["Finding"], "properties": {"severity": "critical"}},
        {"id": "f2", "labels": ["Finding"], "properties": {"severity": "high"}},
        {"id": "f3", "labels": ["Finding"], "properties": {"severity": "medium"}},
    ],
    "links": [
        {"source": "h1", "target": "e1", "type": "HAS_ENDPOINT"},
        {"source": "h1", "target": "e2", "type": "HAS_ENDPOINT"},
        {"source": "h1", "target": "e3", "type": "HAS_ENDPOINT"},
    ],
}


@pytest.mark.asyncio
async def test_perform_assessment_computes_full_report_from_real_graph_data():
    with respx.mock(assert_all_called=True) as mock:
        graph_route = mock.get(GRAPH_URL).mock(return_value=Response(200, json=RICH_GRAPH))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post(f"/api/v1/assessments/{INVESTIGATION_ID}")

        assert resp.status_code == 200
        body = resp.json()

        # Risk score: base 2.0 + critical*2.0 + high*1.5 + medium*0.8 = 2+2+1.5+0.8 = 6.3
        assert body["risk_score"] == pytest.approx(6.3)

        assert body["hosts_count"] == 1
        assert body["services_count"] == 2
        assert body["endpoints_count"] == 3
        assert body["findings_summary"]["Critical"] == 1
        assert body["findings_summary"]["High"] == 1
        assert body["findings_summary"]["Medium"] == 1

        # CVE correlation: SSH -> CVE-2023-38408, nginx -> CVE-2021-23017
        cve_ids = {c["cve_id"] for c in body["correlated_cves"]}
        assert cve_ids == {"CVE-2023-38408", "CVE-2021-23017"}

        # Technology detection from URL heuristics
        assert "WordPress" in body["technologies"]
        assert "REST API" in body["technologies"]

        # Target prioritization: /admin/login should outrank /api/v1/users
        # which should outrank the wp-content JS endpoint, and host should
        # be correctly resolved via the HAS_ENDPOINT link back to the host.
        top = body["prioritized_targets"][0]
        assert "admin" in top["reason"].lower()
        assert top["host"] == "shop.example.com"
        assert body["prioritized_targets"][0]["risk_score"] >= body["prioritized_targets"][1]["risk_score"]

        # Validation plan: the >=5.0 risk admin endpoint should generate a
        # nuclei step; real branching logic, not a canned template.
        actions = [t["action"] for t in body["validation_plan"]]
        assert "run_nuclei_scan" in actions

        assert graph_route.call_count == 1


@pytest.mark.asyncio
async def test_get_assessment_computes_on_the_fly_when_not_cached():
    inv_id = "inv-e2e-not-cached"
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/{inv_id}/graph").mock(
            return_value=Response(200, json=RICH_GRAPH)
        )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.get(f"/api/v1/assessments/{inv_id}")

        assert resp.status_code == 200
        assert resp.json()["investigation_id"] == inv_id


@pytest.mark.asyncio
async def test_get_assessment_uses_cache_and_does_not_recompute():
    """After a POST computes and caches a report, a subsequent GET must
    return the cached result WITHOUT hitting graph_db again."""
    with respx.mock(assert_all_called=False) as mock:
        graph_route = mock.get(GRAPH_URL).mock(return_value=Response(200, json=RICH_GRAPH))

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            post_resp = await ac.post(f"/api/v1/assessments/{INVESTIGATION_ID}")
            assert post_resp.status_code == 200
            assert graph_route.call_count == 1

            get_resp = await ac.get(f"/api/v1/assessments/{INVESTIGATION_ID}")
            assert get_resp.status_code == 200
            assert graph_route.call_count == 1, (
                "GET should serve the cached report, not recompute against graph_db"
            )
            assert get_resp.json() == post_resp.json()


@pytest.mark.asyncio
async def test_graph_db_error_status_passed_through():
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/nonexistent/graph").mock(
            return_value=Response(404, json={"detail": "Investigation not found"})
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v1/assessments/nonexistent")
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_graph_db_unreachable_returns_500_not_a_crash():
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/unreachable-test/graph").mock(
            side_effect=ConnectionError("graph_db is down")
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v1/assessments/unreachable-test")
        assert resp.status_code == 500
        assert "Graph DB" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_empty_graph_falls_back_to_baseline_validation_plan():
    """An investigation with no data yet must still produce a valid report
    with the documented fallback plan, not an error."""
    with respx.mock(assert_all_called=True) as mock:
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/empty-inv/graph").mock(
            return_value=Response(200, json={"nodes": [], "links": []})
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            resp = await ac.post("/api/v1/assessments/empty-inv")
        assert resp.status_code == 200
        body = resp.json()
        assert body["hosts_count"] == 0
        assert body["risk_score"] == pytest.approx(2.0)  # base score, no findings
        assert len(body["validation_plan"]) == 1
        assert body["validation_plan"][0]["action"] == "run_nmap_scan"
        assert body["validation_plan"][0]["target"] == "localhost"
