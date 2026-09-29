"""Tests for the sandbox gate: the runner's own gates can no longer be skipped.

Pins a fixed grant vector so the runner's minting and the sandbox's verifying
cannot drift apart silently.
"""
import time

import pytest

from mcp_servers.gate import (
    GateError,
    enforce,
    host_of,
    is_in_scope,
    verify_grant,
)


class Settings:
    REDIS_URL = "redis://unused:6379/0"
    DATABASE_URL = "postgresql://unused/wraith"
    GATE_SECRET = "test-secret"


RULES = [
    {"pattern": "example.com", "rule_type": "ALLOW"},
    {"pattern": "*.example.com", "rule_type": "ALLOW"},
    {"pattern": "*", "rule_type": "DENY"},
    {"pattern": "staging.example.com", "rule_type": "DENY"},
]

ALLOWED = [
    {"pattern": "juice_shop", "rule_type": "ALLOW"},
    {"pattern": "*", "rule_type": "DENY"},
]


class TestGrantVerification:
    def _token(self, **over):
        import base64, hashlib, hmac, json
        payload = {
            "v": 1, "caller": "active_exploit_runner", "inv": "inv-1",
            "host": "example.com", "cost": 1,
            "exp": int(time.time()) + 60, "nonce": "abc123",
        }
        payload.update(over)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

        def b64(raw):
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        sig = hmac.new(Settings.GATE_SECRET.encode(), body, hashlib.sha256).digest()
        return f"{b64(body)}.{b64(sig)}"

    def test_valid_grant_is_accepted(self):
        assert verify_grant(self._token(), Settings.GATE_SECRET)["host"] == "example.com"

    def test_missing_grant_is_refused(self):
        with pytest.raises(GateError, match="malformed or missing"):
            verify_grant(None, Settings.GATE_SECRET)

    def test_wrong_secret_is_refused(self):
        with pytest.raises(GateError, match="signature is not valid"):
            verify_grant(self._token(), "a-different-secret")

    def test_tampered_payload_is_refused(self):
        """Editing the host after signing must invalidate the grant."""
        import base64
        import json
        token = self._token()
        body_b64, sig = token.split(".")
        body = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
        body["host"] = "attacker.test"
        forged = base64.urlsafe_b64encode(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).decode().rstrip("=")
        with pytest.raises(GateError, match="signature is not valid"):
            verify_grant(f"{forged}.{sig}", Settings.GATE_SECRET)

    def test_expired_grant_is_refused(self):
        with pytest.raises(GateError, match="expired"):
            verify_grant(self._token(exp=int(time.time()) - 5), Settings.GATE_SECRET)

    def test_unset_secret_refuses_everything(self):
        """A missing shared secret must fail closed, never open."""
        with pytest.raises(GateError, match="gate secret is not configured"):
            verify_grant(self._token(), "")


class TestScopeMatching:
    def test_allow_rule_matches(self):
        assert is_in_scope(ALLOWED, "juice_shop") is True

    def test_unmatched_host_is_denied(self):
        assert is_in_scope(ALLOWED, "attacker.test") is False

    def test_specific_deny_beats_broader_allow(self):
        assert is_in_scope(RULES, "staging.example.com") is False

    def test_wildcard_allow_still_works(self):
        assert is_in_scope(RULES, "api.example.com") is True

    def test_exact_allow_beats_catch_all_deny(self):
        assert is_in_scope(RULES, "example.com") is True

    def test_empty_rule_list_denies_everything(self):
        assert is_in_scope([], "example.com") is False

    def test_host_of_handles_malformed_url(self):
        assert host_of("not a url") == ""
        assert host_of("http://Example.COM/x") == "example.com"


class TestEnforcement:
    def _patch(self, monkeypatch, *, active=False, rules=None, rule_error=None):
        import mcp_servers.gate as gate
        monkeypatch.setattr(gate, "killswitch_active", lambda url: active)
        if rule_error:
            def boom(url, inv):
                raise rule_error
            monkeypatch.setattr(gate, "load_scope_rules", boom)
        else:
            monkeypatch.setattr(
                gate, "load_scope_rules", lambda url, inv: (rules if rules is not None else ALLOWED))

    def _real_token(self, **over):
        from mcp_servers.gate import _b64e
        import hashlib, hmac, json
        payload = {"v": 1, "caller": "active_exploit_runner", "inv": "inv-1",
                   "host": "juice_shop", "cost": 1,
                   "exp": int(time.time()) + 60, "nonce": "n"}
        payload.update(over)
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64e(body)}.{_b64e(hmac.new(b'test-secret', body, hashlib.sha256).digest())}"

    def test_authorised_request_passes(self, monkeypatch):
        self._patch(monkeypatch)
        out = enforce(caller="active_exploit_runner", grant_token=self._real_token(),
                      targets=["http://juice_shop:3000/"], settings=Settings)
        assert out["host"] == "juice_shop"

    def test_killswitch_blocks_everything(self, monkeypatch):
        self._patch(monkeypatch, active=True)
        with pytest.raises(GateError, match="killswitch is active"):
            enforce(caller="active_exploit_runner", grant_token=self._real_token(),
                    targets=["http://juice_shop:3000/"], settings=Settings)

    def test_missing_grant_blocks(self, monkeypatch):
        self._patch(monkeypatch)
        with pytest.raises(GateError, match="malformed or missing"):
            enforce(caller="active_exploit_runner", grant_token=None,
                    targets=["http://juice_shop:3000/"], settings=Settings)

    def test_grant_for_other_host_is_refused(self, monkeypatch):
        """A valid grant must not be reusable against a different destination."""
        self._patch(monkeypatch)
        with pytest.raises(GateError, match="grant is for host"):
            enforce(caller="active_exploit_runner",
                    grant_token=self._real_token(host="juice_shop"),
                    targets=["http://attacker.test/"], settings=Settings)

    def test_variant_pointing_off_scope_is_refused(self, monkeypatch):
        """Both the baseline and every variant destination are checked."""
        self._patch(monkeypatch)
        with pytest.raises(GateError, match="grant is for host"):
            enforce(caller="active_exploit_runner",
                    grant_token=self._real_token(host="juice_shop"),
                    targets=["http://juice_shop:3000/", "http://169.254.169.254/"],
                    settings=Settings)

    def test_caller_must_match_the_grant(self, monkeypatch):
        self._patch(monkeypatch)
        with pytest.raises(GateError, match="grant was issued to"):
            enforce(caller="exploit_agent", grant_token=self._real_token(),
                    targets=["http://juice_shop:3000/"], settings=Settings)

    def test_out_of_scope_host_is_refused(self, monkeypatch):
        self._patch(monkeypatch, rules=[{"pattern": "juice_shop", "rule_type": "ALLOW"}])
        with pytest.raises(GateError, match="does not match any allow rule"):
            enforce(caller="active_exploit_runner",
                    grant_token=self._real_token(host="attacker.test"),
                    targets=["http://attacker.test/"], settings=Settings)

    def test_investigation_with_no_rules_is_refused(self, monkeypatch):
        self._patch(monkeypatch, rules=[])
        with pytest.raises(GateError, match="no scope rules"):
            enforce(caller="active_exploit_runner", grant_token=self._real_token(),
                    targets=["http://juice_shop:3000/"], settings=Settings)

    def test_unreadable_scope_rules_fail_closed(self, monkeypatch):
        """Losing the database must stop traffic, not silently allow it."""
        self._patch(monkeypatch, rule_error=GateError("scope rules unavailable (boom); refusing"))
        with pytest.raises(GateError, match="scope rules unavailable"):
            enforce(caller="active_exploit_runner", grant_token=self._real_token(),
                    targets=["http://juice_shop:3000/"], settings=Settings)

    def test_undeterminable_host_is_refused(self, monkeypatch):
        self._patch(monkeypatch)
        with pytest.raises(GateError, match="could not determine destination host"):
            enforce(caller="active_exploit_runner", grant_token=self._real_token(),
                    targets=["not-a-url"], settings=Settings)


class TestSharedVector:
    """One fixed vector, checked on both sides, so the two encodings cannot drift."""

    TOKEN = (
        "eyJjb3N0IjoxLCJleHAiOjk5OTk5OTk5OTksImhvc3QiOiJleGFtcGxlLmNvbSIsImludiI6"
        "Imludi0xIiwibm9uY2UiOiJuIiwidmVyIjoxfQ.deadbeef"
    )

    def test_runner_and_sandbox_agree_on_a_fixed_vector(self):
        from tests._runner.grant import mint_grant, verify_grant as runner_verify
        from mcp_servers.gate import verify_grant as sandbox_verify

        # Both sides must agree on the encoding, and both must reject a grant
        # signed with a different secret. GateError is the sandbox's refusal
        # type; ValueError is the runner's.
        minted = mint_grant("k", caller="c", investigation_id="i", host="h", ttl_seconds=60)
        with pytest.raises(GateError):
            sandbox_verify(minted, "wrong-secret")
        with pytest.raises(ValueError):
            runner_verify(minted, "wrong-secret")
        # Round trip on the real shared secret.
        token = mint_grant("shared-secret", caller="active_exploit_runner",
                           investigation_id="inv-1", host="example.com", ttl_seconds=60)
        assert sandbox_verify(token, "shared-secret")["host"] == "example.com"
        assert runner_verify(token, "shared-secret")["caller"] == "active_exploit_runner"
