"""The graph's trust chain must not be writable by an anonymous caller.

`graph_api` is published on the host, and these routes were the only way to make
a finding *assert* something. An unauthenticated caller could:

  * create a finding carrying a fabricated poc_request/poc_response/
    expected_result/actual_result, which is exactly the evidence
    `require_validation_evidence` asks for, and claim HUMAN_CONFIRMED in the
    same request. The gate checks that those fields are *present*, not that
    anyone executed them, so an invented proof satisfies it;
  * then confirm it through the review route, corroborate it, attach a CVE to it,
    or relabel it DUPLICATE / FALSE_POSITIVE so that a real finding disappears
    from the report.

That is a remote unauthenticated compromise of the audit record, which is the one
thing this system exists to hold. So every route in the chain below requires the
admin token, and the repository must not be reached at all when it is absent.

The assertions here are about the *response*, not about which dependency produced
it: a test that merely checked "some auth exists" would pass against a decorator
on the wrong route.
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock

from app.main import app
from app.config import settings
from app.api.routes import get_repo


TOKEN = "admin-token-fixed-for-this-test"


@pytest.fixture(autouse=True)
def wired_repo():
    """Install the repository override per test.

    Not at import time: other modules in this suite mutate the shared
    `app.dependency_overrides` map (test_agent_sessions pops the entry on
    teardown, test_investigations_mocked clears it), so an import-time override is
    not reliably still present when these tests run.

    The mock also asserts it is never called, which is the part that matters:
    a 401 raised after the write has already been issued would still be a bug.
    """
    repo = AsyncMock()
    repo.create_finding.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.mark_reviewed.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.add_corroboration.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.link_finding_to_cve.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.link_finding_to_session.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.link_finding_to_tool.side_effect = AssertionError(
        "repository reached without a token"
    )
    repo.deduplicate_findings.side_effect = AssertionError(
        "repository reached without a token"
    )

    previous = app.dependency_overrides.get(get_repo)
    app.dependency_overrides[get_repo] = lambda: repo
    yield repo
    if previous is None:
        app.dependency_overrides.pop(get_repo, None)
    else:
        app.dependency_overrides[get_repo] = previous


@pytest.fixture(autouse=True)
def configured_token(monkeypatch):
    monkeypatch.setattr("app.auth.settings.ADMIN_API_TOKEN", TOKEN)


client = TestClient(app)

# For the "the valid token gets through" direction the repository is a stub, so
# routes that declare a response_model will fail response validation and routes
# with no response model will serialise fine. Neither is interesting here; what
# matters is that the request is not refused. Suppressing the exception keeps the
# assertion on the one thing being tested.
lenient_client = TestClient(app, raise_server_exceptions=False)


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"}


# A finding that satisfies require_validation_evidence outright, which is what an
# attacker would send: invented proof plus a validated status in one request.
FORGED_FINDING = {
    "vuln_type": "SQL Injection",
    "severity": "critical",
    "confidence": "high",
    "status": "HUMAN_CONFIRMED",
    "description": "Invented, but shaped like real evidence.",
    "target_id": "endpoint-1",
    "target_type": "endpoint",
    "validation_stage": "EXECUTED",
    "poc_request": "GET /search?q=1' OR '1'='1",
    "poc_response": "HTTP/1.1 200 OK",
    "expected_result": "One row from every table",
    "actual_result": "One row from every table",
}


# (method, path, json, repository method the handler must not reach unauthenticated)
TRUST_CHAIN = [
    ("POST", "/api/v1/findings", FORGED_FINDING, "create_finding"),
    (
        "POST",
        "/api/v1/findings/f-1/review",
        {"decision": "confirmed", "note": "looks right to me"},
        "mark_reviewed",
    ),
    (
        "POST",
        "/api/v1/findings/f-1/corroborate",
        {"source_name": "a-blog-post"},
        "add_corroboration",
    ),
    (
        "POST",
        "/api/v1/findings/f-1/cve",
        {"cve_id": "CVE-2026-0001", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "link_finding_to_cve",
    ),
    ("POST", "/api/v1/findings/f-1/session/s-1", {}, "link_finding_to_session"),
    ("POST", "/api/v1/findings/f-1/tool/t-1", {}, "link_finding_to_tool"),
    ("POST", "/api/v1/investigations/inv-1/dedupe", {}, "deduplicate_findings"),
    ("POST", "/api/v1/programs/prog-1/dedupe", {}, "deduplicate_findings"),
]


@pytest.mark.parametrize("method,path,payload,repo_method", TRUST_CHAIN)
def test_no_token_is_refused(wired_repo, method, path, payload, repo_method):
    response = client.request(method, path, json=payload)
    assert response.status_code == 401, (
        f"{method} {path} accepted an anonymous caller. {repo_method} was "
        f"reachable, which lets an unauthenticated caller rewrite the audit "
        f"record."
    )


@pytest.mark.parametrize("method,path,payload,repo_method", TRUST_CHAIN)
def test_wrong_token_is_refused(wired_repo, method, path, payload, repo_method):
    response = client.request(
        method, path, json=payload, headers={"Authorization": "Bearer " + "x" * len(TOKEN)}
    )
    assert response.status_code == 401


@pytest.mark.parametrize("method,path,payload,repo_method", TRUST_CHAIN)
def test_the_correct_token_is_accepted(wired_repo, method, path, payload, repo_method):
    """Proves the route is reachable at all, i.e. that the guard above is a real
    check rather than a route that 401s for an unrelated reason."""
    # Drop the "must not be reached" side effects for this direction.
    for name in (
        "create_finding",
        "mark_reviewed",
        "add_corroboration",
        "link_finding_to_cve",
        "link_finding_to_session",
        "link_finding_to_tool",
        "deduplicate_findings",
    ):
        getattr(wired_repo, name).side_effect = None

    response = lenient_client.request(method, path, json=payload, headers=_auth())
    assert response.status_code != 401, (
        f"{method} {path} refuses the valid token; the write path is broken, "
        "not merely guarded"
    )


def test_an_unauthenticated_create_cannot_claim_a_validated_status(wired_repo):
    """The headline case, stated separately so the reason survives refactoring:
    forged proof plus a validated status in a single anonymous POST."""
    response = client.post("/api/v1/findings", json=FORGED_FINDING)
    assert response.status_code == 401
    assert wired_repo.create_finding.await_count == 0


def test_the_review_route_rejects_a_decision_from_an_anonymous_caller(wired_repo):
    """Review is the human-in-the-loop step. Unauthenticated, it is just a
    way to mark one's own injected finding confirmed."""
    response = client.post(
        "/api/v1/findings/f-1/review",
        json={"decision": "confirmed", "note": "no evidence required"},
    )
    assert response.status_code == 401
    assert wired_repo.mark_reviewed.await_count == 0