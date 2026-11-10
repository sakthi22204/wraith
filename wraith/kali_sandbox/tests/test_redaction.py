"""Redaction of validation evidence, including the auth-challenge exception."""
import pytest

from mcp_servers.common.redaction import (
    REDACTED,
    extract_session_token,
    redact_capture,
    redact_headers,
    redact_text,
    redact_url,
    scrub_auth_challenge,
)


class TestSensitiveHeaders:
    @pytest.mark.parametrize("name", [
        "authorization", "Authorization", "PROXY-AUTHORIZATION",
        "x-api-key", "x-auth-token",
        "x-csrf-token", "x-xsrf-token", "x-amz-security-token",
        "x-goog-api-key", "x-access-token", "x-session-token",
    ])
    def test_credential_headers_are_fully_masked(self, name):
        out = redact_headers({name: "supersecretvalue"})
        assert out[name] == REDACTED

    def test_authorization_is_still_fully_masked(self):
        out = redact_headers({"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"})
        assert out["Authorization"] == REDACTED

    def test_cookie_name_is_kept_value_masked(self):
        out = redact_headers({"Cookie": "session=abc123; csrf=def456"})
        assert out["Cookie"] == "session=[REDACTED]; csrf=[REDACTED]"
        assert "abc123" not in out["Cookie"]

    def test_set_cookie_attributes_survive(self):
        out = redact_headers({"Set-Cookie": "session=xyz; Path=/; HttpOnly"})
        assert out["Set-Cookie"] == "session=[REDACTED]; Path=/; HttpOnly"

    def test_ordinary_headers_pass_through(self):
        out = redact_headers({"Accept": "application/json", "Content-Type": "text/html"})
        assert out["Accept"] == "application/json"


class TestAuthChallengeScrubbing:
    """A challenge names the scheme; masking it wholesale hides the only clue."""

    def test_scheme_and_error_are_kept(self):
        out = redact_headers({"WWW-Authenticate": 'Bearer error="invalid_token"'})
        assert "Bearer" in out["WWW-Authenticate"]
        assert "invalid_token" in out["WWW-Authenticate"]

    def test_realm_is_kept(self):
        out = redact_headers({"www-authenticate": 'Digest realm="internal"'})
        assert 'realm="internal"' in out["www-authenticate"]

    def test_echoed_jwt_is_still_masked(self):
        leak = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
        out = redact_headers({"www-authenticate": f'Bearer token="{leak}"'})
        assert leak not in out["www-authenticate"]
        assert REDACTED in out["www-authenticate"]

    def test_echoed_long_secret_is_still_masked(self):
        secret = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
        out = redact_headers({"www-authenticate": f'Bearer secret="{secret}"'})
        assert secret not in out["www-authenticate"]

    def test_short_enum_values_are_preserved(self):
        assert scrub_auth_challenge('Basic realm="app"') == 'Basic realm="app"'

    def test_empty_value_is_tolerated(self):
        assert scrub_auth_challenge("") == ""
        assert scrub_auth_challenge(None) is None


class TestSessionTokenExtraction:
    """A confirmed bypass becomes an identity without entering the evidence."""

    def _capture(self, body, status=200, headers=None):
        return {"status_code": status, "response_body": body,
                "response_headers": headers or {}}

    def test_token_in_json_body_is_recovered(self):
        capture = self._capture('{"authentication": {"token": "abc.def.ghi"}}')
        assert extract_session_token(capture) == "abc.def.ghi"

    def test_camel_case_and_nested_keys_are_recovered(self):
        capture = self._capture('{"data": {"accessToken": "tok-123"}}')
        assert extract_session_token(capture) == "tok-123"

    def test_session_cookie_is_recovered(self):
        capture = self._capture(
            "", headers={"Set-Cookie": "connect.sid=s%3Axyz; Path=/; HttpOnly"})
        assert extract_session_token(capture) == "s%3Axyz"

    def test_non_2xx_is_not_harvested(self):
        capture = self._capture('{"token": "abc"}', status=401)
        assert extract_session_token(capture) is None

    def test_a_jwt_in_free_text_is_not_lifted_out(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
        capture = self._capture(f"your debug token is {token}")
        assert extract_session_token(capture) is None

    def test_a_cookie_unrelated_to_auth_is_not_harvested(self):
        capture = self._capture("", headers={"Set-Cookie": "theme=dark; Path=/"})
        assert extract_session_token(capture) is None

    def test_extraction_reads_raw_while_evidence_redacts(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop"
        capture = self._capture(f'{{"token": "{token}"}}')
        assert extract_session_token(capture) == token
        assert token not in redact_capture(capture)["response_body"]
