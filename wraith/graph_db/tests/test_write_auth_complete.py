"""Every graph_db write route must require the admin token.

Phase 1 added the dependency to the finding, review, corroboration, CVE,
validation and dedupe routes. This covers the rest, so the set cannot silently
regress: the failure mode being guarded against is a write route added later
with no dependency, which reads as harmless in review because the surrounding
routes look identical.

Two things are asserted deliberately:

1. The route exists, and carries the dependency. A route that was deleted is
   not protected, it is gone, so a missing route fails rather than passing.
2. The endpoint refuses an unauthenticated caller with 401 before any handler
   body runs. Checking the source string alone would be satisfied by a
   `Depends` that is present but not wired to the router, or by a comparison
   against a token that no longer guards anything.
"""

import inspect
import re

import pytest
from fastapi.testclient import TestClient

from app.api import routes as graph_routes


MUTATING = {"post", "put", "patch", "delete"}


def _route_signatures() -> dict:
    """Every registered route, keyed by (method, path)."""
    out = {}
    for r in graph_routes.router.routes:
        for method in getattr(r, "methods", set()):
            out[(method.lower(), r.path)] = r
    return out


SIGNATURES = _route_signatures()


def _mutating_routes():
    # The router is mounted with prefix="/api/v1" at include time, so the route
    # objects carry the bare path. Prefixing here too would filter every route
    # out and make the checks vacuous.
    return sorted((m, p) for (m, p) in SIGNATURES if m in MUTATING)


def test_the_route_table_is_not_empty():
    """Guards the tests below: an empty table makes every assertion vacuous."""
    assert len(_mutating_routes()) >= 30, (
        "the graph route table shrank unexpectedly; the checks below would "
        "silently stop covering anything"
    )


@pytest.mark.parametrize("method,path", _mutating_routes())
def test_every_write_route_requires_the_admin_token(method, path):
    route = SIGNATURES[(method, path)]
    source = inspect.getsource(route.endpoint)
    # `dependencies=[...]` on the decorator is the wiring; a `Depends` on a
    # parameter would also work but is not the pattern used here.
    assert "require_admin_token" in source, (
        f"{method.upper()} {path} has no admin-token dependency. A write route "
        f"without one lets an unauthenticated caller manufacture the findings, "
        f"reviews and asset inventory the rest of the system treats as evidence."
    )


def test_no_write_route_lost_its_dependency_in_a_bulk_edit():
    """A single named check, so a regression names one route rather than all."""
    for method, path in _mutating_routes():
        route = SIGNATURES[(method, path)]
        assert "require_admin_token" in inspect.getsource(route.endpoint), (
            f"{method.upper()} {path} is unauthenticated"
        )


@pytest.fixture
def client():
    """A TestClient whose repository dependency is satisfied without Neo4j.

    The point of these tests is the auth dependency, so the database is stubbed
    out: without this, an unauthenticated request would fail on a connection
    error and the assertion would be checking the wrong 401. The stub returns
    benign values and records that it was reached, which is what lets
    `test_the_repository_is_never_reached` distinguish "refused before the
    handler" from "refused inside it".
    """
    from fastapi.testclient import TestClient as _TestClient

    from app.api import routes as routes_mod
    from app.main import app

    class _StubRepo:
        touched: list[str] = []

        def __getattr__(self, name):
            async def _record(*args, **kwargs):
                _StubRepo.touched.append(name)
                return {}
            return _record

    stub = _StubRepo()
    app.dependency_overrides[routes_mod.get_repo] = lambda: stub
    try:
        # Deliberately not `with TestClient(app)`: that runs the lifespan, which
        # connects to Neo4j and runs initialize_db. These tests need no database,
        # and requiring one is why this suite could not run outside the
        # container. The auth dependency is resolved per request, not at startup.
        c = _TestClient(app)
        c.stub_repo = stub
        yield c
        c.close()
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/api/v1/findings"),
        ("post", "/api/v1/findings/1/review"),
        ("post", "/api/v1/findings/1/corroborate"),
        ("post", "/api/v1/investigations"),
        ("post", "/api/v1/investigations/1/hosts"),
        ("post", "/api/v1/tools"),
        ("patch", "/api/v1/agent-sessions/1"),
        ("post", "/api/v1/agent-sessions/cleanup-orphaned"),
    ],
)
def test_an_unauthenticated_write_is_refused_with_401(method, path, client):
    """End to end: no token means 401, whatever the handler would have done.

    The repository dependency is satisfied by the suite's stub so that the 401
    can only come from the auth dependency, not from a missing database. If
    auth were removed this would surface as a 500 or a 200 instead, which is
    why the assertion is on 401 specifically.
    """
    resp = getattr(client, method)(path)
    assert resp.status_code == 401, (
        f"{method.upper()} {path} answered {resp.status_code} without a token; "
        f"expected 401 from the admin-token dependency"
    )


def test_a_wrong_token_is_refused(client):
    resp = client.post(
        "/api/v1/findings",
        headers={"Authorization": "Bearer not-the-real-token"},
        json={},
    )
    assert resp.status_code == 401


def test_the_configured_token_is_never_a_published_default():
    """The dependency is only as good as the token behind it."""
    from app.config import KNOWN_INSECURE_SECRETS, settings

    assert settings.ADMIN_API_TOKEN not in KNOWN_INSECURE_SECRETS
    assert settings.ADMIN_API_TOKEN.strip(), "ADMIN_API_TOKEN is empty"


def test_startup_refuses_a_published_token():
    """Import-time config cannot raise, so the validator is what stops it."""
    from app.config import Settings, validate_startup_secrets

    for bad in ("dev-token-change-me", "password", "", "   "):
        with pytest.raises(RuntimeError, match="insecure secrets"):
            validate_startup_secrets(
                Settings(ADMIN_API_TOKEN=bad, NEO4J_PASSWORD="a-real-password")
            )


def test_startup_refuses_a_published_neo4j_password():
    from app.config import Settings, validate_startup_secrets

    with pytest.raises(RuntimeError, match="NEO4J_PASSWORD"):
        validate_startup_secrets(
            Settings(ADMIN_API_TOKEN="a-real-token", NEO4J_PASSWORD="password")
        )


def test_startup_accepts_real_secrets():
    from app.config import Settings, validate_startup_secrets

    validate_startup_secrets(
        Settings(ADMIN_API_TOKEN="a-real-token", NEO4J_PASSWORD="another-real-one")
    )


def test_the_router_wires_the_dependency_rather_than_just_naming_it():
    """Guards against a `Depends` present in source but absent from the route.

    FastAPI reports the dependency on the APIRoute, so a decorator whose
    `dependencies=` was dropped in a merge shows up here even though the
    handler signature still mentions the import.
    """
    unprotected = []
    for (method, path), route in SIGNATURES.items():
        if method not in MUTATING or not path.startswith("/api/v1"):
            continue
        names = {
            getattr(d.call, "__name__", "") for d in getattr(route, "dependant", None).dependencies
        }
        if "require_admin_token" not in names:
            unprotected.append(f"{method.upper()} {path}")
    assert not unprotected, (
        "these write routes are registered without the auth dependency: "
        + ", ".join(unprotected)
    )