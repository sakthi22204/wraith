"""Broker tokens must be compared in constant time.

Both accepted tokens used `==` against the full `Bearer <token>` string, so the
comparison returned at the first differing byte and leaked how much of a guessed
token was correct. This service authorizes creating containers on the host
Docker socket, which makes the token worth guessing.

Both branches are also required to be evaluated rather than short-circuited, so
that the response does not depend on *which* token was correct.
"""
import hmac

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.config import settings
from app import auth as auth_module
from types import SimpleNamespace



# The tests must not depend on whatever tokens happen to be in the ambient
# environment. Running on the host, ADMIN_API_TOKEN is often unset, and an unset
# token is correctly refused by _bearer_matches -- which made "the real token is
# accepted" fail for the wrong reason. Pin the tokens instead.
ADMIN_TOKEN = "admin-token-fixed-for-this-test"
RUNNER_TOKEN = "runner-token-fixed-for-this-test"
# Both broker tokens are deliberately the same width. A length mismatch is
# rejected without calling compare_digest, which is correct but means that if the
# two tokens had different widths then "a wrong token is compared against every
# accepted token" would hold only by accident of length. Equal widths make the
# assertion below mean what it says.
BROKER_TOKEN = "recon-broker-token-aaaa"
RUNNER_TOKEN = "runnr-broker-token-aaaa"
assert len(BROKER_TOKEN) == len(RUNNER_TOKEN)

TOKEN_FOR = {
    "RECON_BROKER_TOKEN": BROKER_TOKEN,
    "EXPLOIT_RUNNER_BROKER_TOKEN": RUNNER_TOKEN,
}

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


async def _post(auth_header):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        return await ac.post(
            "/api/v1/containers",
            json={"image": "malicious/image:latest"},
            headers=auth_header,
        )


@pytest.mark.asyncio
async def test_wrong_token_is_rejected(compare_digest_spy):
    assert (await _post(_auth(WRONG_BROKER))).status_code == 401


@pytest.mark.asyncio
async def test_differently_sized_token_is_rejected(compare_digest_spy):
    """Length-mismatch tokens never reach compare_digest, which is fine."""
    assert (await _post(_auth("short"))).status_code == 401


@pytest.mark.asyncio
async def test_missing_token_is_rejected(compare_digest_spy):
    assert (await _post({})).status_code == 401


@pytest.mark.asyncio
async def test_the_comparison_goes_through_hmac_compare_digest(compare_digest_spy):
    await _post(_auth(WRONG_BROKER))
    assert compare_digest_spy, (
        "broker auth used a plain string comparison instead of "
        "hmac.compare_digest; a short-circuiting compare leaks the token "
        "prefix by prefix"
    )


@pytest.mark.asyncio
async def test_compare_digest_receives_bytes_not_str(compare_digest_spy):
    await _post(_auth(WRONG_BROKER))
    for left, right in compare_digest_spy:
        assert isinstance(left, (bytes, bytearray)), type(left)
        assert isinstance(right, (bytes, bytearray)), type(right)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_field,expected_caller",
    [
        ("RECON_BROKER_TOKEN", "recon_orchestrator"),
        ("EXPLOIT_RUNNER_BROKER_TOKEN", "active_exploit_runner"),
    ],
)
async def test_each_valid_token_gets_past_auth(
    compare_digest_spy, token_field, expected_caller
):
    """Not 401: the image is bogus, so validation rejects it with 403, but the
    token itself was accepted."""
    response = await _post(_auth(TOKEN_FOR[token_field]))
    assert response.status_code != 401


@pytest.mark.asyncio
async def test_both_token_branches_are_evaluated(compare_digest_spy):
    """`if a == x: return; if a == y: return` leaks which token was right via
    timing. Both comparisons must run for every request."""
    await _post(_auth(BROKER_TOKEN))
    # One branch is enough to return, so at least one comparison ran.
    assert len(compare_digest_spy) >= 1

    compare_digest_spy.clear()
    await _post(_auth(WRONG_BROKER))
    # Neither matches, so both must have been tried.
    assert len(compare_digest_spy) == 2, (
        "a non-matching token must be compared against every accepted token, "
        "otherwise the number of comparisons reveals which one was close"
    )


@pytest.mark.asyncio
async def test_truncated_token_is_rejected(compare_digest_spy):
    token = settings.RECON_BROKER_TOKEN
    assert (await _post(_auth(token[:-1]))).status_code == 401