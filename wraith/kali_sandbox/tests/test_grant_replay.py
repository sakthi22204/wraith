"""A grant is single-use.

`mint_grant` has put a random `nonce` in the payload since it was written, and
nothing has ever read it. `verify_grant` checks the signature and the expiry and
stops there, so a grant captured in transit -- from a proxy log, a debug echo, an
exception message that quotes the headers -- stayed valid for its full TTL
(DEFAULT_TTL_SECONDS = 120) and could be replayed as many times as an attacker
liked, within that window.

The signature means the token was minted by the runner. It does not mean this is
the first time it has been shown. Only a store of spent nonces can tell the
difference, and the runner's own validation path mints a fresh grant per request,
so single-use costs nothing legitimate.

Redis is the only shared store both services can reach. It is the same Redis the
killswitch lives in, and `killswitch_active` already treats it as
authoritative-and-fail-closed; the nonce store follows that precedent. If Redis
cannot be reached there is no way to know whether a nonce was already spent, and
the honest answer to "have I seen this before?" when you cannot ask is no.
"""
import time

import pytest

from mcp_servers.gate import (
    GateError,
    enforce,
    spend_nonce,
)


class Settings:
    REDIS_URL = "redis://unused:6379/0"
    DATABASE_URL = "postgresql://unused/wraith"
    GATE_SECRET = "test-secret"

    def __init__(self, redis_url=REDIS_URL):
        self.REDIS_URL = redis_url
        self.DATABASE_URL = "postgresql://unused/wraith"
        self.GATE_SECRET = "test-secret"


ALLOWED = [
    {"pattern": "juice_shop", "rule_type": "ALLOW"},
    {"pattern": "*", "rule_type": "DENY"},
]


class FakeRedis:
    """Enough of redis-py for the nonce store: SADD, which returns 0 for a
    member the set already has.

    Keyed the way Redis is, because the store scopes nonces per investigation --
    a flat member set would make two investigations sharing a nonce collide, and
    would hide that bug rather than show it.

    Deliberately exposes only `sadd`, the name redis-py actually has. An earlier
    version of this stub offered `add`, which the real client does not implement,
    so every test here passed while production raised AttributeError and refused
    all traffic with a 500. A fake that is more permissive than the real thing
    hides exactly the bug it should catch.
    """

    def __init__(self):
        self.spent = {}
        self.calls = []

    def sadd(self, key, value):
        self.calls.append((key, value))
        bucket = self.spent.setdefault(key, set())
        if value in bucket:
            return 0
        bucket.add(value)
        return 1

    def delete(self, key):
        pass

    def __getattr__(self, name):
        # Anything the gate calls that is not sadd is a bug, not a passing test.
        raise AttributeError(
            f"FakeRedis does not implement {name!r}; redis-py's set command is "
            "sadd, and the gate must not invent another"
        )


class UnreachableRedis:
    def __getattr__(self, name):
        def boom(*a, **kw):
            raise ConnectionError("redis unreachable")
        return boom


class TestNonceStore:
    def _token(self, **over):
        from mcp_servers.gate import _b64e
        import hashlib, hmac, json
        payload = {"v": 1, "caller": "active_exploit_runner", "inv": "inv-1",
                   "host": "juice_shop:3000", "cost": 1,
                   "exp": int(time.time()) + 60, "nonce": "nonce-abc"}
        payload.update(over)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64e(body)}.{_b64e(hmac.new(b'test-secret', body, hashlib.sha256).digest())}"

    def _patch(self, monkeypatch, *, active=False, redis=None):
        import mcp_servers.gate as gate
        monkeypatch.setattr(gate, "killswitch_active", lambda url: active)
        monkeypatch.setattr(gate, "load_scope_rules", lambda url, inv: ALLOWED)
        monkeypatch.setattr(gate, "_redis_client", lambda url: redis)

    def test_a_nonce_is_spent_on_first_use(self, monkeypatch):
        self._patch(monkeypatch, redis=FakeRedis())
        assert spend_nonce(self._token(), Settings()) is True

    def test_the_same_grant_cannot_be_spent_twice(self, monkeypatch):
        self._patch(monkeypatch, redis=FakeRedis())
        token = self._token()
        assert spend_nonce(token, Settings()) is True
        with pytest.raises(GateError, match="already been used"):
            spend_nonce(token, Settings())

    def test_two_grants_with_distinct_nonces_are_both_usable(self, monkeypatch):
        """Single-use must not break concurrent legitimate traffic: the runner
        mints per request, so two requests hold two grants."""
        self._patch(monkeypatch, redis=FakeRedis())
        assert spend_nonce(self._token(nonce="n1"), Settings()) is True
        assert spend_nonce(self._token(nonce="n2"), Settings()) is True

    def test_an_unreachable_store_refuses_rather_than_allows(self, monkeypatch):
        """Fail closed.

        Not being able to ask "have I seen this nonce?" is not the same as "no".
        Allowing here would mean the replay protection is available exactly when
        the attacker can also cause the outage.
        """
        self._patch(monkeypatch, redis=UnreachableRedis())
        with pytest.raises(GateError, match="unavailable"):
            spend_nonce(self._token(), Settings())

    def test_a_missing_redis_url_refuses(self, monkeypatch):
        self._patch(monkeypatch, redis=None)
        with pytest.raises(GateError):
            spend_nonce(self._token(), Settings(redis_url=""))

    def test_an_unsigned_token_is_refused_before_the_store_is_touched(self, monkeypatch):
        """Spend happens after signature verification, so a forged nonce cannot
        push a real one out of the store."""
        self._patch(monkeypatch, redis=FakeRedis())
        with pytest.raises(GateError):
            spend_nonce("forged.token", Settings())

    def test_enforce_rejects_a_replayed_grant(self, monkeypatch):
        """The end-to-end property, at the boundary callers actually use."""
        redis = FakeRedis()
        self._patch(monkeypatch, redis=redis)
        token = self._token()

        out = enforce(caller="active_exploit_runner", grant_token=token,
                      targets=["http://juice_shop:3000/"], settings=Settings())
        assert out["host"] == "juice_shop:3000"

        with pytest.raises(GateError, match="already been used"):
            enforce(caller="active_exploit_runner", grant_token=token,
                    targets=["http://juice_shop:3000/"], settings=Settings())

    def test_an_expired_grant_is_not_recorded_as_spent(self, monkeypatch):
        """Ordering: a token that fails verification must not be burned, or an
        attacker could invalidate grants they only ever saw."""
        redis = FakeRedis()
        self._patch(monkeypatch, redis=redis)
        expired = self._token(exp=int(time.time()) - 10)
        with pytest.raises(GateError, match="expired"):
            spend_nonce(expired, Settings())
        assert redis.spent == {}
        assert redis.calls == [], "an unverifiable token must not reach the store"

    def test_the_nonce_is_keyed_by_grant_secret_scope(self, monkeypatch):
        """Two investigations with the same nonce must not collide, and one
        investigation's spend must not block another's."""
        redis = FakeRedis()
        self._patch(monkeypatch, redis=redis)
        assert spend_nonce(self._token(nonce="same"), Settings()) is True
        assert spend_nonce(self._token(nonce="same", inv="inv-2"), Settings()) is True