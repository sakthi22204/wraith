"""The nonce store is exercised against the real redis-py client.

`tests/test_grant_replay.py` uses a stub for the replay logic. This covers the
part a stub cannot: that the method the gate calls exists on an actual
`redis.Redis`, and behaves the way the single-use check depends on.

It caught a real defect. The stub offered `add()` and the gate called `add()`;
redis-py spells it `sadd`, so against a live Redis every gated request died with
AttributeError -- surfaced as a 500 that refused all traffic, including entirely
legitimate probes. Every replay test passed, because the fake agreed with the
mistake.

The tests skip when Redis is unreachable rather than faking it, since the whole
point is to test the real client.
"""
import secrets

import pytest


REDIS_URL = "redis://redis:6379/0"


@pytest.fixture(scope="module")
def client():
    redis = pytest.importorskip("redis")
    try:
        c = redis.Redis.from_url(REDIS_URL, socket_timeout=3)
        c.ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"redis not reachable at {REDIS_URL}: {exc}")
    return c


def test_the_gate_calls_a_method_redis_actually_has(client):
    """The regression, stated as a property.

    `Redis.add` does not exist. If the gate reaches for anything other than a
    real command name, this fails at import-free attribute access instead of at
    the first request in production.
    """
    assert not hasattr(client, "add"), (
        "redis-py has no add(); if this ever becomes true the gate's stub and "
        "the real client have diverged for a different reason"
    )
    assert callable(client.sadd)


def test_sadd_reports_membership_so_it_can_be_a_replay_check(client):
    key = f"gate:spent_nonce:test:{secrets.token_hex(6)}"
    try:
        assert client.sadd(key, "nonce-1") == 1, "first insert must report new"
        assert client.sadd(key, "nonce-1") == 0, "second insert must report present"
        # A different member is independently new, which is what keeps two
        # investigations from blocking each other.
        assert client.sadd(key, "nonce-2") == 1
    finally:
        client.delete(key)


def test_the_gate_enforces_single_use_against_real_redis(client, monkeypatch):
    """End to end through gate.spend_nonce, on the real client."""
    import mcp_servers.gate as gate
    from mcp_servers.config import settings

    import json
    import time
    import hashlib
    import hmac

    def _b64(raw):
        import base64
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    host = "juice_shop:3000"
    nonce = secrets.token_hex(8)
    payload = {"v": 1, "caller": "active_exploit_runner", "inv": "replay-test",
               "host": host, "cost": 1, "exp": int(time.time()) + 60, "nonce": nonce}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    token = f"{_b64(body)}.{_b64(hmac.new(settings.GATE_SECRET.encode(), body, hashlib.sha256).digest())}"

    key = f"{gate.NONCE_KEY_PREFIX}:replay-test"
    client.delete(key)
    try:
        assert gate.spend_nonce(token, settings) is True
        try:
            gate.spend_nonce(token, settings)
        except gate.GateError as exc:
            assert "already been used" in exc.detail
            assert exc.status_code == 403
        else:
            pytest.fail("a second use of the same grant was accepted")

        # redis-py decodes members as bytes unless decode_responses is set, so
        # compare on that basis rather than assuming either convention.
        assert client.smembers(key) == {nonce.encode()}, (
            "the nonce should be recorded in the store the gate claims to use"
        )
    finally:
        client.delete(key)