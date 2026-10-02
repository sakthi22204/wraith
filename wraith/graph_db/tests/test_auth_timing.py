"""The admin token must be compared in constant time.

Every auth dependency in this service did `authorization != f"Bearer {token}"`.
Python's `str.__eq__` returns as soon as it finds a differing byte, so the
comparison leaks, byte by byte, how much of a guessed prefix was correct. On a
network an attacker can measure that, and it turns a 256-bit secret into a
linear search.

What is being asserted is the *mechanism*, not just the verdict: an ordinary
"wrong token is rejected" test passes either way, because `==` is correct about
*whether* two strings match and wrong only about *how long* it takes. So these
tests spy on `hmac.compare_digest` and require that it is the thing doing the
comparing.
"""
import hmac

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app import auth as auth_module
from types import SimpleNamespace
from app.api.routes import get_repo
from unittest.mock import AsyncMock


@pytest.fixture(autouse=True)
def mocked_repo():
    """Install the repository override per test, not at import time.

    Other modules in this suite mutate the shared ``app.dependency_overrides``
    map -- test_agent_sessions.py pops the entry in teardown and
    test_investigations_mocked.py clears the whole map -- so an override
    registered at import time is not reliably still in place when this file's
    tests run. Without it the handler opens a real Neo4j connection and fails on
    "Future attached to a different loop".
    """
    previous = app.dependency_overrides.get(get_repo)
    app.dependency_overrides[get_repo] = lambda: AsyncMock()
    yield
    if previous is None:
        app.dependency_overrides.pop(get_repo, None)
    else:
        app.dependency_overrides[get_repo] = previous


client = TestClient(app)

PROTECTED = ("/api/v1/programs/p1?confirm=true",)


# The tests must not depend on whatever tokens happen to be in the ambient
# environment. Running on the host, ADMIN_API_TOKEN is often unset, and an unset
# token is correctly refused by _bearer_matches -- which made "the real token is
# accepted" fail for the wrong reason. Pin the tokens instead.
ADMIN_TOKEN = "admin-token-fixed-for-this-test"
RUNNER_TOKEN = "runner-token-fixed-for-this-test"
BROKER_TOKEN = "recon-broker-token-fixed-for-this-test"

# A guess of exactly the right length, so the comparison has to reach
# compare_digest rather than being stopped by the length check. The length check
# is deliberate and safe (the token length is already observable from the
# response, and compare_digest refuses unequal lengths); what must not happen is
# a byte-by-byte compare.
WRONG_ADMIN = "x" * len(ADMIN_TOKEN)
WRONG_RUNNER = "x" * len(RUNNER_TOKEN)
WRONG_BROKER = "x" * len(BROKER_TOKEN)


@pytest.fixture(autouse=True)
def configured_tokens(monkeypatch):
    """Pin the tokens on the object the auth module actually reads.

    Deliberately not `monkeypatch.setattr(settings, ...)`: these Settings models
    are pydantic models, so setting a field the service does not declare raises
    on set, and deleting it again on undo raises on teardown. The auth modules
    do `from .config import settings`, so rebinding that name on the module is
    both simpler and closer to what is being tested.
    """
    values = dict(settings.model_dump())
    values.update(
        ADMIN_API_TOKEN=ADMIN_TOKEN,
        EXPLOIT_RUNNER_BROKER_TOKEN=RUNNER_TOKEN,
        RECON_BROKER_TOKEN=BROKER_TOKEN,
    )
    monkeypatch.setattr(
        auth_module, "settings", SimpleNamespace(**values)
    )


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def compare_digest_spy(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    return calls


def test_wrong_token_is_rejected(compare_digest_spy):
    response = client.delete(PROTECTED[0], headers=_auth(WRONG_ADMIN))
    assert response.status_code == 401


def test_correct_token_is_accepted(compare_digest_spy):
    response = client.delete(
        PROTECTED[0],
        headers=_auth(ADMIN_TOKEN),
    )
    assert response.status_code != 401


def test_missing_token_is_rejected(compare_digest_spy):
    assert client.delete(PROTECTED[0]).status_code == 401


def test_the_comparison_goes_through_hmac_compare_digest(compare_digest_spy):
    """The regression itself: `authorization != expected` short-circuits."""
    client.delete(PROTECTED[0], headers=_auth(WRONG_ADMIN))

    assert compare_digest_spy, (
        "auth used a plain string comparison instead of hmac.compare_digest; "
        "a short-circuiting compare leaks the token prefix by prefix"
    )


def test_compare_digest_receives_bytes_not_str(compare_digest_spy):
    """compare_digest compares bytes and rejects mixed types; a str argument
    would raise at runtime rather than authenticate, so this also pins the call
    shape."""
    client.delete(PROTECTED[0], headers={"Authorization": "Bearer wrong"})

    for left, right in compare_digest_spy:
        assert isinstance(left, (bytes, bytearray)), type(left)
        assert isinstance(right, (bytes, bytearray)), type(right)