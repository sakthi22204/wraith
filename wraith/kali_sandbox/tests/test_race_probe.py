"""Tests for http_probe_race: the concurrency harness for single-use actions.

These run against the local Juice Shop, like the other http_probe tests: the
point of the primitive is that the captures reflect requests that really
overlapped, so mocking the transport would test nothing.
"""
import asyncio

import pytest

from mcp_servers.http_probe_server import (
    MAX_RACE_REQUESTS,
    HttpProbeServer,
)

srv = HttpProbeServer()


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
