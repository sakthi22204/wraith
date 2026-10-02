"""Coverage rendering in the markdown report.

An empty findings table is ambiguous on its own. These tests pin that the
report says which kind of empty it is, and that a report still renders when the
coverage block is unavailable.
"""
import datetime

import pytest
from jinja2 import Environment, FileSystemLoader

from app.clients.assessment_client import AssessmentClient
from app.models import ProgramReport

COVERAGE = {
    "endpoints_discovered": 51,
    "javascript_bundles": 3,
    "api_endpoints": 48,
    "findings_recorded": 1,
    "candidate_families": ["SQL Injection", "XSS"],
    "validations_run": 1,
    "validations_inconclusive": 0,
    "findings_confirmed": 1,
    "gaps": [],
}


@pytest.fixture(scope="module")
def template():
    env = Environment(loader=FileSystemLoader("app/templates"))
    return env.get_template("finding_report.md.j2")


def render(template, coverage, findings=None):
    return template.render(
        program_name="Juice Shop",
        generated_at=datetime.datetime.utcnow(),
        findings=findings or [],
        summary_line=None,
        coverage=coverage,
    )


def test_renders_the_coverage_table(template):
    out = render(template, COVERAGE)

    assert "## Assessment Coverage" in out
    assert "| Endpoints discovered | 51 |" in out
    assert "| API routes identified | 48 |" in out
    assert "| Findings confirmed | 1 |" in out


def test_lists_the_families_exercised(template):
    out = render(template, COVERAGE)

    assert "SQL Injection" in out
    assert "XSS" in out


def test_renders_gaps_when_present(template):
    out = render(template, {**COVERAGE, "gaps": ["No API routes were discovered."]})

    assert "Known gaps" in out
    assert "No API routes were discovered." in out


def test_no_gaps_section_when_coverage_is_complete(template):
    out = render(template, COVERAGE)

    assert "Known gaps" not in out


def test_omits_the_section_when_coverage_is_unavailable(template):
    """The assessment service may be down; the report must still render."""
    out = render(template, None)

    assert "## Assessment Coverage" not in out
    assert "# Vulnerability Report" in out


def test_report_still_renders_with_findings_and_coverage(template):
    finding = {
        "title": "SQL injection in product search",
        "severity": "High",
        "cvss_score": 8.8,
        "description": "d",
        "vulnerability_type": "SQL Injection",
        "ai_confidence": 0.8,
        "affected_asset": "http://t/rest/products/search",
        "steps_to_reproduce": "s",
        "discovery_metadata": {"status": "CONFIRMED"},
    }
    out = render(template, COVERAGE, findings=[finding])

    assert "SQL injection in product search" in out
    assert "## Assessment Coverage" in out


# -- the client ------------------------------------------------------------

def test_client_returns_none_when_the_service_is_unreachable():
    """A report must not fail because a dependency is down."""
    client = AssessmentClient(base_url="http://127.0.0.1:1")

    import asyncio
    assert asyncio.run(client.get_coverage("inv-1")) is None


def test_client_returns_the_coverage_block():
    import asyncio

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url):
            import httpx
            return httpx.Response(200, json={"coverage": COVERAGE}, request=httpx.Request("GET", url))

    import httpx
    original = httpx.AsyncClient
    httpx.AsyncClient = FakeClient
    try:
        out = asyncio.run(AssessmentClient().get_coverage("inv-1"))
    finally:
        httpx.AsyncClient = original

    assert out == COVERAGE


@pytest.mark.asyncio
async def test_generator_attaches_coverage_to_the_report():
    """The wiring, not just the template: the report must actually carry the
    block the assessment computed."""
    from unittest.mock import AsyncMock, patch
    from app.generator import generator

    coverage = {
        "endpoints_discovered": 67,
        "javascript_bundles": 3,
        "api_endpoints": 52,
        "findings_recorded": 1,
        "candidate_families": ["SQL Injection"],
        "validations_run": 1,
        "validations_inconclusive": 0,
        "findings_confirmed": 1,
        "gaps": [],
    }

    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as audit, \
         patch("app.generator.assessment_client", new_callable=AsyncMock) as assess:
        graph.get_program.return_value = {"name": "Juice Shop"}
        graph.get_findings_for_program.return_value = []
        audit.get_audit_entries.return_value = []
        assess.get_coverage.return_value = coverage

        report = await generator.generate_program_report("inv-1")

    assert assess.get_coverage.await_count == 1
    assert report.coverage == coverage


@pytest.mark.asyncio
async def test_generator_still_reports_when_coverage_lookup_fails():
    from unittest.mock import AsyncMock, patch
    from app.generator import generator

    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as audit, \
         patch("app.generator.assessment_client", new_callable=AsyncMock) as assess:
        graph.get_program.return_value = {"name": "Juice Shop"}
        graph.get_findings_for_program.return_value = []
        audit.get_audit_entries.return_value = []
        assess.get_coverage.return_value = None

        report = await generator.generate_program_report("inv-1")

    assert report.coverage is None
    assert report.investigation_name == "Juice Shop"


def test_report_model_carries_coverage():
    report = ProgramReport(
        investigation_name="Juice Shop",
        generated_at=datetime.datetime.utcnow(),
        findings=[],
        coverage=COVERAGE,
    )

    assert report.coverage["api_endpoints"] == 48


def test_coverage_defaults_to_absent_not_empty_dict():
    report = ProgramReport(
        investigation_name="Juice Shop",
        generated_at=datetime.datetime.utcnow(),
        findings=[],
    )

    assert report.coverage is None
