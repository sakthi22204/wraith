"""Readiness gate before the deterministic validation pass.

Recon is the heaviest load a target sees, and a container can be mid-restart
when validation starts. Probing into that restart does not produce evidence --
it produces connect_error captures, which are honest observations about a
server that was not listening and dishonest inputs to a verdict. The gate waits
for one plain GET to answer before any candidate budget is spent.
"""
import asyncio

import httpx
import pytest

from app.orchestrator import ReconOrchestrator


class _Client:
    """httpx.AsyncClient stand-in whose GET fails until ``failures`` run out."""

    def __init__(self, failures: int, status: int = 200):
        self.failures = failures
        self.status = status
        self.calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, follow_redirects=False):
        self.calls += 1
        if self.calls <= self.failures:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(self.status, request=httpx.Request("GET", url))


@pytest.mark.asyncio
async def test_ready_target_passes_on_the_first_probe(monkeypatch):
    client = _Client(failures=0)
    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)

    assert await ReconOrchestrator._wait_for_target(["http://x.test:3000"], timeout=5)
    assert client.calls == 1


@pytest.mark.asyncio
async def test_a_restarting_target_is_waited_for_rather_than_probed(monkeypatch):
    client = _Client(failures=2)
    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)

    slept = []

    real_sleep = asyncio.sleep
    async def fake_sleep(seconds):
        slept.append(seconds)
        await real_sleep(0)

    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    assert await ReconOrchestrator._wait_for_target(["http://x.test:3000"], timeout=30)
    assert client.calls == 3
    assert slept


@pytest.mark.asyncio
async def test_an_unreachable_target_is_reported_as_not_ready(monkeypatch):
    client = _Client(failures=10_000)
    monkeypatch.setattr("httpx.AsyncClient", lambda **kw: client)

    real_sleep = asyncio.sleep
    async def fake_sleep(seconds):
        await real_sleep(0)
    monkeypatch.setattr("asyncio.sleep", fake_sleep)

    assert await ReconOrchestrator._wait_for_target(
        ["http://x.test:3000"], timeout=0) is False
