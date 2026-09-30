"""Tests for http_probe: request construction, capture fidelity, and hardening."""
import asyncio

import json

import pytest

from mcp_servers.http_probe_server import (
    HttpProbeServer,
    MAX_REQUEST_BODY,
    ProbeCapture,
)
from mcp_servers.common.redaction import (
    REDACTED,
    redact_body,
    redact_headers,
    redact_text,
)

srv = HttpProbeServer()


class TestUrlValidation:
    def test_accepts_plain_http(self):
        assert srv._validate_url("http://juice_shop:3000/metrics")

    def test_rejects_non_http_scheme(self):
        with pytest.raises(ValueError, match="Only http"):
            srv._validate_url("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with pytest.raises(ValueError, match="Credentials"):
            srv._validate_url("http://user:pass@juice_shop:3000/")

    def test_rejects_missing_host(self):
        with pytest.raises(ValueError, match="must include a host"):
            srv._validate_url("http:///nohost")

    def test_rejects_oversized_url(self):
        with pytest.raises(ValueError, match="4096"):
            srv._validate_url("http://h/" + "a" * 5000)


class TestMethodValidation:
    def test_normalizes_case(self):
        assert srv._validate_method("post") == "POST"

    def test_rejects_unknown_verb(self):
        with pytest.raises(ValueError, match="not allowed"):
            srv._validate_method("TRACE")


class TestHeaderValidation:
    def test_rejects_header_injection(self):
        with pytest.raises(ValueError, match="newlines"):
            srv._validate_headers({"X-A": "v\r\nInjected: 1"})

    def test_allows_host_override_for_host_header_hypotheses(self):
        """Host is settable: it changes only the Host line to the destination
        already resolved from the URL, so routing/scope are unchanged while
        Host-header/cache-poisoning hypotheses become testable."""
        assert srv._validate_headers({"Host": "wraith-hostpoison.invalid"}) == {
            "Host": "wraith-hostpoison.invalid"}

    def test_rejects_client_controlled_headers(self):
        with pytest.raises(ValueError, match="cannot be set"):
            srv._validate_headers({"Content-Length": "123"})

    def test_rejects_too_many_headers(self):
        with pytest.raises(ValueError, match="50 headers"):
            srv._validate_headers({f"X-H{i}": "v" for i in range(51)})

    def test_accepts_normal_headers(self):
        assert srv._validate_headers({"Accept": "text/html"}) == {"Accept": "text/html"}


class TestBodyValidation:
    def test_rejects_oversized_body(self):
        with pytest.raises(ValueError, match="exceeds"):
            srv._validate_body("a" * (MAX_REQUEST_BODY + 1))

    def test_accepts_a_json_object_body(self):
        """A JSON body is the normal case for REST and JSON-RPC endpoints.

        The MCP argument layer decodes a JSON-looking string back into a dict,
        so a string-only contract made every JSON-bodied request unsendable.
        """
        assert json.loads(srv._validate_body({"a": 1})) == {"a": 1}

    def test_accepts_a_json_array_body(self):
        assert json.loads(srv._validate_body([1, 2])) == [1, 2]

    def test_passes_a_plain_string_through_unchanged(self):
        assert srv._validate_body("a=1&b=2") == "a=1&b=2"

    def test_rejects_a_body_that_is_not_serializable(self):
        with pytest.raises(ValueError, match="not JSON-serializable"):
            srv._validate_body({"when": object()})

    def test_rejects_a_type_that_is_neither_string_nor_json(self):
        with pytest.raises(ValueError, match="must be a string or a JSON"):
            srv._validate_body(12345)

    def test_none_body_stays_none(self):
        assert srv._validate_body(None) is None

    def test_rejects_oversized_json_object(self):
        with pytest.raises(ValueError, match="exceeds"):
            srv._validate_body({"k": "a" * MAX_REQUEST_BODY})


class TestRedaction:
    def test_redacts_auth_and_cookie_headers(self):
        out = redact_headers({"Authorization": "Bearer sk-secret", "Cookie": "session=abc", "Accept": "json"})
        assert out["Authorization"] == REDACTED
        assert out["Cookie"] == "session=[REDACTED]"
        assert "abc" not in out["Cookie"]
        assert out["Accept"] == "json"

    def test_redacts_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assert REDACTED in redact_text(f"token is {jwt}")

    def test_redacts_assignment_but_keeps_key(self):
        out = redact_text("password=hunter2&user=admin")
        assert "hunter2" not in out
        assert "password" in out
        assert "admin" in out

    def test_redacts_vendor_keys(self):
        assert REDACTED in redact_text("key sk-abcdefghijklmnopqrstuvwx")
        assert REDACTED in redact_text("ghp_abcdefghijklmnopqrstuvwxyz1234")

    def test_redacts_pii_in_json_body(self):
        body = '{"email":"a@b.com","password":"p","name":"keep"}'
        out = redact_body(body, "application/json")
        # Structure-aware redaction returns a dict, not the original string.
        assert out["email"] == REDACTED
        assert out["password"] == REDACTED
        assert out["name"] == "keep"

    def test_redacts_form_body(self):
        out = redact_body("email=x@y.com&name=bob", "application/x-www-form-urlencoded")
        assert "x@y.com" not in out
        assert "bob" in out

    def test_leaves_plain_text_readable(self):
        # Over-redaction destroys reproducibility, which is the whole point of
        # the evidence, so ordinary text must survive intact.
        text = "Prometheus metrics for juice_shop at /metrics"
        assert redact_text(text) == text


# Sends real requests to juice_shop on the compose network, so these are
# part of the live proof rather than the host-runnable subset.
@pytest.mark.integration
class TestCaptureAgainstLiveTarget:
    """Real requests against the local Juice Shop. No mocking: the point of
    this feature is that the capture reflects what actually came back."""

    @pytest.mark.asyncio
    async def test_probe_reaches_real_endpoint(self):
        cap = await srv.probe("http://juice_shop:3000/metrics", timeout=20)
        assert cap.reached_target is True, f"target unreachable: {cap.error}"
        assert cap.status_code == 200
        assert "juiceshop_llm" in cap.response_body
        assert cap.elapsed_ms is not None
        assert len(cap.body_sha256) == 64

    @pytest.mark.asyncio
    async def test_probe_spa_fallback_exposes_false_positive(self):
        """This is the swagger-api false positive: a 200 that proves nothing."""
        cap = await srv.probe("http://juice_shop:3000/api-docs/swagger.json", timeout=20)
        assert cap.status_code == 200
        assert "json" not in cap.content_type.lower()
        assert "<!DOCTYPE" in cap.response_body.upper()[:200]

    @pytest.mark.asyncio
    async def test_capture_records_request_for_replay(self):
        cap = await srv.probe("http://juice_shop:3000/rest/user/login",
                              method="POST", headers={"Content-Type": "application/json"},
                              body='{"email":"a@b.co","password":"p"}', timeout=20)
        assert cap.request_method == "POST"
        assert cap.request_body is not None
        # The request body is evidence; PII in it must be masked but the
        # structure must survive so a human can still replay it.
        assert "a@b.co" not in (cap.request_body or "")
        assert "password" in (cap.request_body or "")

    @pytest.mark.asyncio
    async def test_unreachable_target_reports_error_not_exception(self):
        cap = await srv.probe("http://127.0.0.1:9/nothing", timeout=3)
        assert cap.reached_target is False
        assert cap.error

    @pytest.mark.asyncio
    async def test_default_user_agent_injected_when_absent(self):
        cap = await srv.probe("http://juice_shop:3000/metrics", timeout=20)
        ua = (cap.request_headers or {}).get("User-Agent", "")
        assert ua.startswith("Mozilla/5.0"), f"expected browser UA, got {ua!r}"

    @pytest.mark.asyncio
    async def test_explicit_user_agent_is_respected(self):
        cap = await srv.probe("http://juice_shop:3000/metrics",
                              headers={"User-Agent": "wraith-test/1.0"}, timeout=20)
        assert (cap.request_headers or {}).get("User-Agent") == "wraith-test/1.0"


# Sends real requests to juice_shop on the compose network, so these are
# part of the live proof rather than the host-runnable subset.
@pytest.mark.integration
class TestConcurrency:
    @pytest.mark.asyncio
    async def test_parallel_probes_are_independent(self):
        """Concurrent probes must not cross-contaminate each other's captures."""
        urls = [f"http://juice_shop:3000/api/Products?page={i}" for i in range(5)]
        caps = await asyncio.gather(*(srv.probe(u, timeout=20) for u in urls))
        assert all(c.reached_target for c in caps), [c.error for c in caps]
        # Each capture must correspond to its own request, not a shared result.
        assert [c.request_url for c in caps] == urls
        # Distinct pages return distinct bodies; identical hashes would mean a
        # response was served to the wrong request.
        assert len({c.body_sha256 for c in caps}) > 1
