"""The admin token must be compared in constant time.

`authorization == f"Bearer {token}"` short-circuits at the first differing byte,
which leaks how much of a guessed token was correct. These tests spy on
`hmac.compare_digest` and require that it is what performs the comparison -- an
ordinary "wrong token is rejected" test passes with `==` too, because `==` is
correct about the verdict and wrong only about how long it takes to reach it.
"""
import hmac

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings
from app import auth as auth_module
from app.api import routes as routes_module
from types import SimpleNamespace


client = TestClient(app)

PROTECTED = "/api/v1/reports/inv-1"

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
def stubbed_generator(monkeypatch):
    """The report handler calls graph_db. Stub it so that "the token got past
    auth" is observable as a 200, instead of a ConnectError from a service that
    is not running in a unit test."""

    class FakeReport:
        def model_dump(self):
            return {"investigation_id": "inv-1", "findings": []}

    async def fake_generate(investigation_id, *args, **kwargs):
        return FakeReport()

    monkeypatch.setattr(
        routes_module.generator, "generate_program_report", fake_generate
    )
    monkeypatch.setattr(
        routes_module.generator, "generate_finding_report", fake_generate
    )


@pytest.fixture
def compare_digest_spy(monkeypatch):
    calls = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    return calls


def _exercise():
    """One same-length wrong token, which is what must trigger the comparison."""
    return client.get(PROTECTED, headers=_auth(WRONG_ADMIN))


def test_wrong_token_is_rejected(compare_digest_spy):
    assert _exercise().status_code == 401


def test_missing_token_is_rejected(compare_digest_spy):
    assert client.get(PROTECTED).status_code == 401


def test_the_comparison_goes_through_hmac_compare_digest(compare_digest_spy):
    _exercise()
    assert compare_digest_spy, (
        "auth used a plain string comparison instead of hmac.compare_digest; "
        "a short-circuiting compare leaks the token prefix by prefix"
    )


def test_compare_digest_receives_bytes_not_str(compare_digest_spy):
    """compare_digest rejects mixed types, so a str argument would raise at
    runtime rather than authenticate. This pins the call shape too."""
    _exercise()
    for left, right in compare_digest_spy:
        assert isinstance(left, (bytes, bytearray)), type(left)
        assert isinstance(right, (bytes, bytearray)), type(right)


def test_correct_token_gets_past_auth(compare_digest_spy, stubbed_generator):
    """Not 401. Whatever happens downstream (upstream service down, unknown id)
    is irrelevant here; this only proves the token was accepted."""
    response = client.get(
        f"{PROTECTED}?format=json", headers=_auth(ADMIN_TOKEN)
    )
    assert response.status_code == 200


def test_truncated_token_is_rejected(compare_digest_spy):
    response = client.get(PROTECTED, headers=_auth(settings.ADMIN_API_TOKEN[:-1]))
    assert response.status_code == 401


def test_differently_sized_token_is_rejected(compare_digest_spy):
    """Length-mismatch tokens never reach compare_digest, which is fine."""
    assert client.get(PROTECTED, headers=_auth("short")).status_code == 401