"""Report profiles select structure, never eligibility.

A confirmed finding with an incomplete evidence manifest stays confirmed but is
marked unsubmittable; a profile cannot promote an unvalidated hypothesis.
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.generator import generator
from app.profiles import (
    evidence_gaps,
    guidance_for,
    is_submittable,
    resolve_profile,
)


def finding(**overrides):
    base = {
        "id": "f1",
        "title": "IDOR on /api/users",
        "vuln_type": "Broken Access Control",
        "severity": "high",
        "confidence": 0.9,
        "status": "AI_VALIDATED",
        "description": "Object reference is not checked against the caller.",
        "poc_request": "GET /api/users/2 HTTP/1.1",
        "poc_response": "HTTP/1.1 200 OK",
        "expected_result": "403 for a different account",
        "actual_result": "200 with the other account's email",
        "discovered_at": "2026-01-01T12:00:00Z",
        "target_id": "t1",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "evidence": "redacted",
        "validation_stage": "IMPACT_CONFIRMED",
    }
    base.update(overrides)
    return base


def test_auto_profile_follows_engagement_mode():
    assert resolve_profile(None, "wapt") == "hackerone"
    assert resolve_profile(None, "redteam") == "redteam"
    assert resolve_profile(None, "both") == "redteam"


def test_explicit_profile_wins_and_unknown_is_an_error():
    assert resolve_profile("bugcrowd", "redteam") == "bugcrowd"
    with pytest.raises(ValueError):
        resolve_profile("nonsense", "wapt")


def test_every_profile_has_guidance():
    for profile in ("bugcrowd", "hackerone", "redteam", "final"):
        guidance = guidance_for(profile)
        assert guidance["reader"]
        assert guidance["required_sections"]
        assert guidance["notes"]


def test_missing_evidence_is_a_gap_not_a_confirmation_change():
    assert evidence_gaps(finding()) == []
    assert is_submittable(finding(validation_state="CONFIRMED"))

    incomplete = finding(validation_state="CONFIRMED", poc_response=None, actual_result=None)
    assert "no captured response" in evidence_gaps(incomplete)
    assert "no actual result" in evidence_gaps(incomplete)


@pytest.mark.asyncio
async def test_program_report_derives_profile_and_marks_evidence_gaps():
    program = {"name": "Example", "engagement_mode": "redteam"}
    confirmed = finding()
    # Status says validated but the response was never captured. The report
    # must keep it and flag the gap rather than silently promoting it.
    confirmed["poc_response"] = None

    with patch("app.generator.graph_db_client", new_callable=AsyncMock) as graph, \
         patch("app.generator.audit_client", new_callable=AsyncMock) as audit, \
         patch("app.generator.assessment_client", new_callable=AsyncMock) as assess:
        graph.get_program.return_value = program
        graph.get_findings_for_program.return_value = [confirmed]
        graph.get_target_details.return_value = None
        graph.get_discovering_tool.return_value = None
        audit.get_audit_entries.return_value = []
        assess.get_coverage.return_value = None

        report = await generator.generate_program_report("p1")

    assert report.report_profile == "redteam"
    assert report.submission_guidance["reader"] == "Client security owner"
    assert report.evidence_warnings
    assert report.findings[0].validation_state == "CONFIRMED"
    assert report.findings[0].submittable is False
