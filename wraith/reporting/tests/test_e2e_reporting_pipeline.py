"""
End-to-end test for the reporting service.

GAP THIS FILLS: the existing test_api.py hits the real HTTP routes with
real auth, but explicitly mocks `graph_db_client`, `generator.generate_finding_report`,
and `generator.generate_program_report` entirely
(`patch("app.api.routes.graph_db_client", new_callable=AsyncMock)`, etc.).
The real generator logic (CWE mapping, CVSS scoring, timeline construction,
attack graph text, executive summary) is unit-tested separately in
test_generator.py, test_cvss_calculator.py, test_cwe_mapping.py -- but never
through the real HTTP endpoint. And graph_db_client / audit_client's real
outbound httpx calls have never been exercised at all.

This test drives the real app via real HTTP with real auth, and mocks ONLY
graph_db and active_exploit_runner's audit endpoint at the wire level
(respx) -- the two genuinely external systems. Routing, auth, the real
graph_db_client/audit_client httpx calls, the full generator pipeline, real
Jinja2 template rendering, and real weasyprint PDF export all run
unmodified.
"""
import pytest
import respx
from httpx import AsyncClient, ASGITransport, Response

from app.main import app
from app.config import settings

AUTH = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
PROGRAM_ID = "prog-e2e-1"

GRAPH_JSON = {
    "nodes": [
        {"id": "prog1", "labels": ["Investigation"], "properties": {"name": "E2E Test Program"}},
        {"id": "h1", "labels": ["Host"], "properties": {"value": "shop.example.com"}},
        {"id": "e1", "labels": ["Endpoint"], "properties": {"url": "/api/v1/login"}},
        {"id": "f1", "labels": ["Finding"], "properties": {"severity": "critical"}},
        {"id": "tool1", "labels": ["Tool"], "properties": {"name": "sqlmap"}},
    ],
    "links": [
        {"source": "h1", "target": "e1", "type": "HAS_ENDPOINT"},
        {"source": "f1", "target": "tool1", "type": "DISCOVERED_BY"},
    ],
}

FINDING = {
    "id": "f1",
    "vuln_type": "sqli",
    "description": "SQL injection in login form",
    "severity": "critical",
    "target_id": "e1",
    "confidence": "0.95",
    "discovered_at": "2026-01-15T10:00:00Z",
    # AI_VALIDATED is the status the graph writes for an executed validation.
    # The legacy "CONFIRMED" alias is deliberately not a confirmation path on
    # its own (see test_unvalidated_not_reported_as_vulnerability.py): without
    # a recorded exchange it is an unvalidated hypothesis.
    "status": "AI_VALIDATED",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}


def _mock_backends(mock, findings=(FINDING,), audit_entries=()):
    mock.get(f"{settings.GRAPH_DB_URL}/investigations/{PROGRAM_ID}/graph").mock(
        return_value=Response(200, json=GRAPH_JSON)
    )
    mock.get(f"{settings.GRAPH_DB_URL}/investigations/{PROGRAM_ID}/findings").mock(
        return_value=Response(200, json=list(findings))
    )
    mock.get(f"{settings.ACTIVE_EXPLOIT_RUNNER_URL}/audit/{PROGRAM_ID}").mock(
        return_value=Response(200, json=list(audit_entries))
    )


@pytest.mark.asyncio
async def test_finding_report_markdown_end_to_end():
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(
                f"/api/v1/reports/{PROGRAM_ID}/findings/f1?format=markdown", headers=AUTH
            )

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/markdown")
        text = resp.text

        # Real CWE mapping ran (sqli -> CWE-89 per cwe_mapping.py), not a stub.
        assert "CWE-89" in text
        # Real CVSS calculation ran against the real vector -> should be a 9.x critical score.
        assert "9." in text
        # Real graph traversal resolved the affected host via the Endpoint link.
        assert "shop.example.com" in text
        # Real graph_db_client.get_discovering_tool found the DISCOVERED_BY link.
        assert "sqlmap" in text


@pytest.mark.asyncio
async def test_finding_report_json_end_to_end_full_fields():
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(
                f"/api/v1/reports/{PROGRAM_ID}/findings/f1?format=json", headers=AUTH
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["vulnerability_type"].startswith("CWE-89")
        assert body["severity"] == "Critical"
        assert "shop.example.com" in body["affected_asset"]
        assert body["attack_graph"]["total_hops"] >= 1
        assert body["risk_rating"]["score"] > 9.0


@pytest.mark.asyncio
async def test_finding_report_pdf_end_to_end_produces_real_pdf_bytes():
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(
                f"/api/v1/reports/{PROGRAM_ID}/findings/f1?format=pdf", headers=AUTH
            )

        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        # Real weasyprint output -- a real PDF file signature, not a mock.
        assert resp.content[:4] == b"%PDF"
        assert len(resp.content) > 500


@pytest.mark.asyncio
async def test_finding_not_found_returns_404_through_real_lookup():
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)  # findings list only contains f1

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(
                f"/api/v1/reports/{PROGRAM_ID}/findings/does-not-exist?format=json", headers=AUTH
            )
        assert resp.status_code == 404


@pytest.mark.asyncio
async def test_program_report_end_to_end_excludes_duplicates_and_false_positives():
    findings = [
        FINDING,
        {**FINDING, "id": "f2", "status": "DUPLICATE"},
        {**FINDING, "id": "f3", "status": "FALSE_POSITIVE"},
        {**FINDING, "id": "f4", "severity": "medium", "vuln_type": "xss", "status": "CONFIRMED",
         "cvss_vector": None, "target_id": "e1"},
    ]
    audit_entries = [
        {"action": "run_sqlmap", "target": "shop.example.com", "result": "Confirmed injectable parameter",
         "timestamp": "2026-01-15T11:00:00Z"}
    ]
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock, findings=findings, audit_entries=audit_entries)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(f"/api/v1/reports/{PROGRAM_ID}?format=json", headers=AUTH)

        assert resp.status_code == 200
        body = resp.json()

        # Only the 2 CONFIRMED findings should appear; duplicate/false-positive excluded.
        assert len(body["findings"]) == 2
        returned_ids = {f["title"] for f in body["findings"]}
        assert len(returned_ids) == 2

        # Real executive summary computed from real severity counts.
        assert body["executive_summary"]["severity_breakdown"]["Critical"] == 1
        assert body["executive_summary"]["overall_posture"] == "HIGH RISK / ACTION REQUIRED"

        # Real audit_client call surfaced into the program timeline.
        timeline_events = [e["event"] for e in body["timeline"]]
        assert any("run_sqlmap" in e for e in timeline_events)


@pytest.mark.asyncio
async def test_program_report_markdown_and_pdf_also_run_end_to_end():
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            md_resp = await ac.get(f"/api/v1/reports/{PROGRAM_ID}?format=markdown", headers=AUTH)
            pdf_resp = await ac.get(f"/api/v1/reports/{PROGRAM_ID}?format=pdf", headers=AUTH)

        assert md_resp.status_code == 200
        assert md_resp.headers["content-type"].startswith("text/markdown")

        assert pdf_resp.status_code == 200
        assert pdf_resp.content[:4] == b"%PDF"


@pytest.mark.asyncio
async def test_legacy_program_alias_routes_produce_identical_results():
    """The /reports/program/{id} alias routes must behave identically to
    /reports/{id} -- verified by actually calling both through real HTTP,
    not by inspecting that they call the same function."""
    with respx.mock(assert_all_called=False) as mock:
        _mock_backends(mock)

        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            primary = await ac.get(f"/api/v1/reports/{PROGRAM_ID}?format=json", headers=AUTH)
            alias = await ac.get(f"/api/v1/reports/program/{PROGRAM_ID}?format=json", headers=AUTH)

        assert primary.status_code == alias.status_code == 200
        primary_body = primary.json()
        alias_body = alias.json()
        primary_body.pop("generated_at", None)
        alias_body.pop("generated_at", None)
        assert primary_body == alias_body


@pytest.mark.asyncio
async def test_graph_db_down_surfaces_as_error_not_a_silent_empty_report():
    with respx.mock(assert_all_called=False) as mock:
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/{PROGRAM_ID}/graph").mock(
            side_effect=ConnectionError("graph_db unreachable")
        )
        mock.get(f"{settings.GRAPH_DB_URL}/investigations/{PROGRAM_ID}/findings").mock(
            return_value=Response(200, json=[FINDING])
        )
        mock.get(f"{settings.ACTIVE_EXPLOIT_RUNNER_URL}/audit/{PROGRAM_ID}").mock(
            return_value=Response(200, json=[])
        )
        async with AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as ac:
            resp = await ac.get(f"/api/v1/reports/{PROGRAM_ID}?format=json", headers=AUTH)
        assert resp.status_code == 500
