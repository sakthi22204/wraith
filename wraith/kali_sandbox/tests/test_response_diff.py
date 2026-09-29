"""Tests for differential comparison, the diff engine, and authz signals."""
import pytest

from mcp_servers.common.response_diff import (
    classify_differential,
    scan_leaks,
    summarize_differential,
)
from mcp_servers.http_probe_server import (
    HttpProbeServer,
    Identity,
    ProbeVariant,
    _authz_signal,
    _merge_variant,
    _scrub_identity_headers,
)


def cap(status=200, body="", headers=None, ms=10.0, final_url="http://x/"):
    return {
        "status_code": status,
        "response_body": body,
        "response_headers": headers or {},
        "elapsed_ms": ms,
        "final_url": final_url,
        "content_type": "text/html",
    }


# -- diff engine ------------------------------------------------------------

class TestMateriality:
    def test_identical_is_not_material(self):
        r = classify_differential(cap(body="same"), cap(body="same"))
        assert r["material"] is False
        assert r["identical"] is True

    def test_status_transition_is_material(self):
        r = classify_differential(cap(200, "a"), cap(500, "a"))
        assert r["material"] is True
        assert any("500" in s for s in r["signals"])

    def test_newly_exposed_value_shape_is_material(self):
        r = classify_differential(
            cap(200, "<p>hi</p>"), cap(200, "<p>hi alice@corp.com</p>")
        )
        assert r["material"] is True
        assert "email" in r["body"]["newly_exposed_patterns"]

    def test_security_header_appearing_is_material(self):
        r = classify_differential(
            cap(403, "d"), cap(200, "ok", {"www-authenticate": "Bearer"})
        )
        assert r["material"] is True
        assert "www-authenticate" in r["headers"]["security_relevant_added"]

    def test_volatile_field_drift_is_not_material(self):
        """A nonce or timestamp changing says nothing about the request."""
        h = {"content-type": "application/json"}
        b = '{"nonce":"aaa","data":"x"}'
        v = '{"nonce":"zzz","data":"x"}'
        r = classify_differential(cap(200, b, h), cap(200, v, h))
        assert r["material"] is False
        assert r["volatile_only"] is True

    def test_timing_above_threshold_is_material(self):
        r = classify_differential(cap(200, "s", ms=10.0), cap(200, "s", ms=3500.0))
        assert r["material"] is True

    def test_timing_jitter_is_not_material(self):
        """Network jitter alone must not read as a timing side channel."""
        h = {"content-type": "text/html"}
        r = classify_differential(cap(200, "s", h, ms=100.0), cap(200, "s", h, ms=400.0))
        assert r["material"] is False

    def test_timing_is_material_even_when_content_identical(self):
        r = classify_differential(cap(200, "s", ms=10.0), cap(200, "s", ms=3500.0))
        assert r["body"]["identical"] is True
        assert r["material"] is True

    def test_effective_url_change_is_material(self):
        r = classify_differential(
            cap(200, "a", final_url="http://x/a"),
            cap(200, "a", final_url="http://x/b"),
        )
        assert r["material"] is True

    def test_summary_is_human_readable(self):
        r = classify_differential(cap(200, "a"), cap(500, "a"))
        assert "status changed" in summarize_differential(r)

    def test_no_material_difference_says_so(self):
        r = classify_differential(cap(200, "a"), cap(200, "a"))
        assert "equivalent" in summarize_differential(r)


class TestLeakScanning:
    @pytest.mark.parametrize("body,expected", [
        ("contact bob@example.com", "email"),
        ("id 550e8400-e29b-41d4-a716-446655440000", "uuid"),
        ("java.lang.NullPointerException at A.java:1", "stack_trace"),
        ("SQLSTATE[42S02]: bad", "sql_error"),
        ("AKIAIOSFODNN7EXAMPLE", "aws_key"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij",
         "bearer_token"),
        ("db at 10.1.2.3 responded", "internal_hostname"),
    ])
    def test_detects_shape(self, body, expected):
        assert expected in scan_leaks(body)

    def test_clean_body_has_no_leaks(self):
        assert scan_leaks("<p>nothing interesting</p>") == []


# -- variant merging -------------------------------------------------------

class TestVariantMerge:
    def test_omitted_fields_inherit_baseline(self):
        base = {"url": "http://x/", "method": "GET", "headers": {"A": "1"},
                "body": "b", "timeout": 20.0}
        merged = _merge_variant(base, ProbeVariant(label="only body"))
        assert merged["url"] == "http://x/"
        assert merged["method"] == "GET"
        assert merged["headers"] == {"A": "1"}
        assert merged["body"] == "b"

    def test_header_override_applies(self):
        base = {"url": "http://x/", "method": "GET", "headers": {"A": "1"}, "timeout": 20.0}
        merged = _merge_variant(base, ProbeVariant(headers={"A": "2"}))
        assert merged["headers"] == {"A": "2"}

    def test_empty_header_value_removes_header(self):
        """An empty value is how a caller drops a header it inherited."""
        base = {"url": "http://x/", "method": "GET", "headers": {"A": "1", "B": "2"},
                "timeout": 20.0}
        merged = _merge_variant(base, ProbeVariant(headers={"A": ""}))
        assert "A" not in merged["headers"]
        assert merged["headers"]["B"] == "2"


# -- authorization signals -------------------------------------------------

class TestAuthzSignal:
    def test_identical_content_across_identities_is_a_lead(self):
        s = _authz_signal("user_a", "user_b", cap(200, "alice's order"),
                          cap(200, "alice's order"))
        assert s is not None
        assert "identical" in s

    def test_privilege_escalation_is_flagged(self):
        """A second identity getting in where the first was refused."""
        s = _authz_signal("user_a", "user_b", cap(403, "denied"), cap(200, "secret"))
        assert s is not None
        assert "allowed" in s and "403" in s

    def test_lower_identity_refused_is_not_a_bug(self):
        assert _authz_signal("user_a", "user_b", cap(200, "a"), cap(403, "denied")) is None

    def test_same_identity_raises_nothing(self):
        assert _authz_signal("user_a", "user_a", cap(200, "a"), cap(200, "b")) is None

    def test_no_baseline_identity_raises_nothing(self):
        """Without an identified control there is no cross-identity claim."""
        assert _authz_signal("", "user_b", cap(200, "a"), cap(200, "a")) is None

    def test_escalation_message_names_correct_identities(self):
        """A swapped label here would misstate the finding in a report."""
        s = _authz_signal("user_a", "user_b", cap(403, "d"), cap(200, "s"))
        assert "user_b" in s and "user_a" in s
        assert s.index("user_b") < s.index("allowed")


# -- credential hygiene ----------------------------------------------------

class TestCredentialScrubbing:
    def test_identity_headers_never_enter_evidence(self):
        out = _scrub_identity_headers(
            {"request_headers": {"Authorization": "Bearer SUPERSECRET"}, "status_code": 200},
            "user_b",
        )
        assert "SUPERSECRET" not in str(out)
        assert out["identity"] == "user_b"

    def test_headers_without_identity_are_also_masked(self):
        out = _scrub_identity_headers(
            {"request_headers": {"X-Api-Key": "SECRETVALUE"}, "status_code": 200}, ""
        )
        assert "SECRETVALUE" not in str(out)

    def test_capture_is_copied_not_mutated(self):
        original = {"request_headers": {"Authorization": "Bearer X"}, "status_code": 200}
        _scrub_identity_headers(original, "user_a")
        assert original["request_headers"]["Authorization"] == "Bearer X"


# -- compare() behaviour ---------------------------------------------------

class TestCompare:
    @pytest.fixture
    def server(self):
        return HttpProbeServer()

    async def test_requires_at_least_one_variant(self, server):
        with pytest.raises(ValueError, match="at least one variant"):
            await server.compare(url="http://x/", variants=[])

    async def test_variant_count_is_bounded(self, server):
        many = [ProbeVariant(label=f"v{i}") for i in range(99)]
        with pytest.raises(ValueError, match="at most"):
            await server.compare(url="http://x/", variants=many)

    async def test_cross_host_variant_is_refused(self, server):
        """A variant on another host could not be caused by the change."""
        with pytest.raises(ValueError, match="same scheme/host/port"):
            await server.compare(
                url="http://allowed.test/",
                variants=[ProbeVariant(label="evil", url="http://other.test/")],
            )

    async def test_duplicate_identity_labels_rejected(self, server):
        with pytest.raises(ValueError, match="duplicate identity"):
            await server.compare(
                url="http://x/",
                variants=[ProbeVariant(label="v", identity="u")],
                identities=[Identity(label="u"), Identity(label="u")],
            )

    async def test_unknown_identity_is_rejected(self, server):
        with pytest.raises(ValueError, match="unknown identity"):
            await server.compare(
                url="http://x/",
                variants=[ProbeVariant(label="v", identity="ghost")],
                identities=[Identity(label="real")],
            )

    async def test_unknown_baseline_identity_is_rejected(self, server):
        with pytest.raises(ValueError, match="unknown baseline identity"):
            await server.compare(
                url="http://x/", variants=[ProbeVariant(label="v")],
                identities=[Identity(label="real")], baseline_identity="ghost",
            )

    async def test_baseline_identity_headers_are_applied(self, server, monkeypatch):
        sent = {}

        async def fake_probe(url, method="GET", headers=None, body=None, timeout=20.0,
                             follow_redirects=False):
            sent.setdefault("headers", []).append(headers or {})
            return type("C", (), {"model_dump": lambda self: cap(200, "x")})()

        monkeypatch.setattr(server, "probe", fake_probe)
        await server.compare(
            url="http://x/", variants=[ProbeVariant(label="v")],
            identities=[Identity(label="u", headers={"Authorization": "Bearer T"})],
            baseline_identity="u",
        )
        assert sent["headers"][0].get("Authorization") == "Bearer T"
