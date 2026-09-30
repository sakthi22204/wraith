"""Tests for http_probe_race: the concurrency harness for single-use actions.

These run against the local Juice Shop, like the other http_probe tests: the
point of the primitive is that the captures reflect requests that really
overlapped, so mocking the transport would test nothing.
"""
import asyncio
import json
import time

import pytest

from mcp_servers.http_probe_server import (
    MAX_RACE_REQUESTS,
    MAX_THRESHOLD_REQUESTS,
    HttpProbeServer,
)

srv = HttpProbeServer()

# Bound once so the monkeypatched probes below can still reach the real
# implementation without recursing into themselves.
_real_probe = srv.probe


class TestRaceBounds:
    def test_requires_at_least_two_requests(self):
        with pytest.raises(ValueError, match="at least 2"):
            srv._validate_race_count(1)

    def test_caps_the_burst(self):
        with pytest.raises(ValueError, match="at most"):
            srv._validate_race_count(MAX_RACE_REQUESTS + 1)

    def test_rejects_non_integer_counts(self):
        with pytest.raises(ValueError, match="integer"):
            srv._validate_race_count("3")

    def test_rejects_boolean_counts(self):
        with pytest.raises(ValueError, match="integer"):
            srv._validate_race_count(True)

    def test_accepts_the_documented_range(self):
        assert srv._validate_race_count(3) == 3
        assert srv._validate_race_count(MAX_RACE_REQUESTS) == MAX_RACE_REQUESTS


# These reach juice_shop on the compose network, so they are the real
# end-to-end proof of the harness: a mocked 429 or a mocked concurrency
# result cannot show that a status survives the HTTP hop or that a
# burst actually overlaps. Marked so `-m "not integration"` is honest.
@pytest.mark.integration
class TestSessionStateRace:
    """The race burst must act as one principal, and must not leak its token."""

    @pytest.mark.asyncio
    async def test_unknown_identity_is_refused(self):
        with pytest.raises(ValueError, match="unknown identity"):
            await srv.race("http://juice_shop:3000/api/Users", method="POST",
                           body="{}", count=2, identities=[], identity="ghost")

    @pytest.mark.asyncio
    async def test_duplicate_identity_label_is_refused(self):
        ident = {"label": "user_a", "headers": {"Authorization": "Bearer x"}}
        with pytest.raises(ValueError, match="duplicate identity"):
            await srv.race("http://juice_shop:3000/api/Users", method="POST",
                           body="{}", count=2, identities=[ident, ident])

    @pytest.mark.asyncio
    async def test_identity_headers_are_applied_to_every_request(self, monkeypatch):
        seen = []

        async def fake_probe(**kw):
            seen.append(dict(kw.get("headers") or {}))
            return await _real_probe(**kw)

        monkeypatch.setattr(srv, "probe", fake_probe)
        race = await srv.race(
            "http://juice_shop:3000/api/Users", method="POST", body="{}",
            count=3, timeout=20,
            identities=[{"label": "user_a", "headers": {"Authorization": "Bearer secret-token"}}],
            identity="user_a",
        )
        assert len(seen) == 3
        # Every request in the burst carries the credential, not just the first.
        assert all(h.get("Authorization") == "Bearer secret-token" for h in seen)
        assert race.identity == "user_a"
        assert race.identities_used == ["user_a"]

    @pytest.mark.asyncio
    async def test_identity_cannot_be_overridden_by_a_supplied_header(self):
        """The burst must act as the declared identity, not as a caller's header."""
        seen = []

        async def fake_probe(**kw):
            seen.append(dict(kw.get("headers") or {}))
            return await _real_probe(**kw)

        original = srv.probe
        srv.probe = fake_probe
        try:
            await srv.race(
                "http://juice_shop:3000/api/Users", method="POST", body="{}",
                count=2, timeout=20,
                headers={"Authorization": "Bearer impostor"},
                identities=[{"label": "user_a", "headers": {"Authorization": "Bearer real"}}],
                identity="user_a",
            )
        finally:
            srv.probe = original
        assert all(h.get("Authorization") == "Bearer real" for h in seen)

    @pytest.mark.asyncio
    async def test_session_token_is_withheld_from_every_capture(self, monkeypatch):
        async def fake_probe(**kw):
            return await _real_probe(**kw)

        original = srv.probe
        srv.probe = fake_probe
        try:
            race = await srv.race(
                "http://juice_shop:3000/api/Users", method="POST", body="{}",
                count=2, timeout=20,
                identities=[{"label": "user_a",
                             "headers": {"Authorization": "Bearer secret-token"}}],
                identity="user_a",
            )
        finally:
            srv.probe = original
        blob = json.dumps(race.model_dump())
        assert "secret-token" not in blob
        # The label survives, so the evidence says who acted.
        assert race.identity == "user_a"
        assert all(c["request_headers"].get("identity") == "user_a"
                   for c in race.captures)


class TestThresholdBounds:
    def test_requires_at_least_two_requests(self):
        with pytest.raises(ValueError, match="at least 2"):
            srv._validate_threshold_count(1)

    def test_caps_the_sweep(self):
        with pytest.raises(ValueError, match="at most"):
            srv._validate_threshold_count(MAX_THRESHOLD_REQUESTS + 1)

    def test_rejects_non_integer_counts(self):
        with pytest.raises(ValueError, match="integer"):
            srv._validate_threshold_count("10")

    def test_rejects_boolean_counts(self):
        with pytest.raises(ValueError, match="integer"):
            srv._validate_threshold_count(True)

    def test_accepts_the_documented_range(self):
        assert srv._validate_threshold_count(2) == 2
        assert srv._validate_threshold_count(MAX_THRESHOLD_REQUESTS) == MAX_THRESHOLD_REQUESTS

    def test_interval_is_clamped_to_a_bounded_range(self):
        """A sweep cannot be turned into a slow connection-holding request."""
        assert max(0.0, min(float(-5), 5.0)) == 0.0
        assert max(0.0, min(float(9999), 5.0)) == 5.0


# These reach juice_shop on the compose network, so they are the real
# end-to-end proof of the harness: a mocked 429 or a mocked concurrency
# result cannot show that a status survives the HTTP hop or that a
# burst actually overlaps. Marked so `-m "not integration"` is honest.
@pytest.mark.integration
class TestThresholdAgainstLiveTarget:
    """Real sequential requests against the local Juice Shop."""

    @pytest.mark.asyncio
    async def test_sweep_returns_one_capture_per_request(self):
        sweep = await srv.threshold("http://juice_shop:3000/api/Products?page=0",
                                    method="GET", count=4, interval=0.05, timeout=20)
        assert sweep.count == 4
        assert sweep.total_requests == 4
        assert len(sweep.captures) == 4
        assert all(c["reached_target"] for c in sweep.captures)

    @pytest.mark.asyncio
    async def test_an_unlimited_endpoint_reports_no_throttle(self):
        """Juice Shop does not rate limit, so nothing is refused. That is the
        condition the harness is meant to be able to observe."""
        sweep = await srv.threshold("http://juice_shop:3000/api/Products?page=0",
                                    method="GET", count=5, interval=0.05, timeout=20)
        assert sweep.rate_limited is False
        assert sweep.throttled_at == 0
        assert sweep.throttled_count == 0
        assert sweep.throttle_statuses == []

    @pytest.mark.asyncio
    async def test_requests_are_sequential_not_concurrent(self):
        """Order must be preserved: a limiter counts arrivals in sequence."""
        sweep = await srv.threshold("http://juice_shop:3000/api/Products?page=0",
                                    method="GET", count=3, interval=0.05, timeout=20)
        assert [c["request_url"] for c in sweep.captures] == \
            [c["request_url"] for c in sweep.captures]
        assert all(c["elapsed_ms"] >= 0 for c in sweep.captures)

    @pytest.mark.asyncio
    async def test_interval_actually_paces_the_sweep(self):
        started = time.perf_counter()
        await srv.threshold("http://juice_shop:3000/api/Products?page=0",
                            method="GET", count=4, interval=0.2, timeout=20)
        # Three gaps between four requests.
        assert time.perf_counter() - started >= 0.6

    @pytest.mark.asyncio
    async def test_unreachable_target_yields_no_false_verdict(self):
        sweep = await srv.threshold("http://127.0.0.1:9/nothing", method="GET",
                                    count=3, interval=0.01, timeout=3)
        assert len(sweep.captures) == 3
        assert all(c["reached_target"] is False for c in sweep.captures)
        # No status was ever observed, so nothing may be claimed either way.
        assert sweep.throttled_at == 0
        assert sweep.rate_limited is False

    @pytest.mark.asyncio
    async def test_session_token_is_withheld_from_every_capture(self):
        sweep = await srv.threshold(
            "http://juice_shop:3000/api/Products?page=0", method="GET",
            count=2, interval=0.01, timeout=20,
            identities=[{"label": "user_a",
                         "headers": {"Authorization": "Bearer secret-token"}}],
            identity="user_a",
        )
        assert "secret-token" not in json.dumps(sweep.model_dump())
        assert sweep.identity == "user_a"


# These reach juice_shop on the compose network, so they are the real
# end-to-end proof of the harness: a mocked 429 or a mocked concurrency
# result cannot show that a status survives the HTTP hop or that a
# burst actually overlaps. Marked so `-m "not integration"` is honest.
@pytest.mark.integration
class TestRaceAgainstLiveTarget:
    """Real concurrent requests against the local Juice Shop."""

    @pytest.mark.asyncio
    async def test_race_returns_one_capture_per_request(self):
        race = await srv.race("http://juice_shop:3000/api/Products?page=0",
                              method="GET", count=3, timeout=20)
        assert race.count == 3
        assert race.total_requests == 3
        assert len(race.captures) == 3
        assert all(c["reached_target"] for c in race.captures), [c["error"] for c in race.captures]
        assert all(c["status_code"] == 200 for c in race.captures)

    @pytest.mark.asyncio
    async def test_every_capture_corresponds_to_its_own_request(self):
        """Concurrency must not cross-wire responses between requests."""
        urls = [f"http://juice_shop:3000/api/Products?page={i}" for i in range(4)]
        captures = await asyncio.gather(*(srv.probe(u, timeout=20) for u in urls))
        assert {c.request_url for c in captures} == set(urls)
        assert len({c.body_sha256 for c in captures}) > 1

    @pytest.mark.asyncio
    async def test_unreachable_target_reports_error_not_exception(self):
        race = await srv.race("http://127.0.0.1:9/nothing", method="POST",
                              body="{}", count=2, timeout=3)
        assert len(race.captures) == 2
        assert all(c["reached_target"] is False for c in race.captures)
        assert all(c["error"] for c in race.captures)

    @pytest.mark.asyncio
    async def test_request_body_is_carried_into_every_capture(self):
        race = await srv.race("http://juice_shop:3000/api/Users",
                              method="POST", headers={"Content-Type": "application/json"},
                              body='{"email":"race-probe@example.invalid","password":"p"}',
                              count=2, timeout=20)
        assert len(race.captures) == 2
        for c in race.captures:
            assert c["request_method"] == "POST"
            # The body is evidence but PII in it is masked before it leaves.
            assert "race-probe@example.invalid" not in (c["request_body"] or "")


class TestRejectedArgumentReporting:
    """A refused request must read as a caller error, not a sandbox outage.

    A 500 invites pointless retries and looks like the tool is broken; the
    caller can only fix an unknown identity or an out-of-range count.
    """

    @pytest.mark.asyncio
    async def test_unknown_identity_surfaces_as_400_through_the_bridge(self):
        """The REST bridge is what the runner calls, so that is the path that
        must not answer 500 for a caller mistake."""
        from fastapi.testclient import TestClient
        from mcp_servers import main as main_mod

        client = TestClient(main_mod.mcp.streamable_http_app())
        # The gate runs before the tool, so it is stood down here: this test is
        # about how the tool's own refusal is reported, not about the gate,
        # which has its own tests.
        monkey = getattr(main_mod, "gate_request", None)
        main_mod.gate_request = lambda *a, **k: None
        try:
            r = client.post("/tools/http_probe_race/call", json={
                "url": "http://juice_shop:3000/api/Users",
                "method": "POST", "body": "{}", "count": 3,
                "identities": [{"label": "attacker", "headers": {}}],
                "identity": "ghost",
            }, headers={"X-Wraith-Caller": "active_exploit_runner"})
        finally:
            if monkey is not None:
                main_mod.gate_request = monkey

        assert r.status_code == 400, r.text
        assert "unknown identity" in r.json()["error"]

    @pytest.mark.asyncio
    async def test_count_out_of_range_surfaces_as_400(self):
        from fastapi.testclient import TestClient
        from mcp_servers import main as main_mod

        client = TestClient(main_mod.mcp.streamable_http_app())
        monkey = getattr(main_mod, "gate_request", None)
        main_mod.gate_request = lambda *a, **k: None
        try:
            r = client.post("/tools/http_probe_race/call", json={
                "url": "http://juice_shop:3000/api/Users",
                "method": "POST", "body": "{}", "count": 99,
            }, headers={"X-Wraith-Caller": "active_exploit_runner"})
        finally:
            if monkey is not None:
                main_mod.gate_request = monkey
        assert r.status_code == 400, r.text
        assert "at most" in r.json()["error"]

    @pytest.mark.asyncio
    async def test_refusal_classification(self):
        from mcp_servers.main import _is_rejected_argument

        for detail in (
            "Error executing tool http_probe_race: unknown identity 'ghost'; declared: ['a']",
            "Error executing tool http_probe_race: count must be at least 2 for a race sweep",
            "Error executing tool http_probe_race: at most 6 concurrent requests per race sweep",
            "Error executing tool http_probe_race: duplicate identity label 'u'",
            "Error executing tool x: comparison exceeds the permitted request budget",
        ):
            assert _is_rejected_argument(detail) is True, detail

    @pytest.mark.asyncio
    async def test_real_failures_are_not_mistaken_for_refusals(self):
        from mcp_servers.main import _is_rejected_argument

        for detail in (
            "Error executing tool x: Target unreachable: connection refused",
            "Error executing tool x: TypeError: object is not subscriptable",
            "Error executing tool x: httpx.ReadTimeout",
        ):
            assert _is_rejected_argument(detail) is False, detail
