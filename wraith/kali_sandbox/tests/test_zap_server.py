"""The ZAP adapter must turn scanner state into an honest tri-state result.

ZAP is an external service, so every failure mode here is an infrastructure
failure rather than a clean scan: a missing key, an unreachable daemon, a scan
that times out. Each of those must be `inconclusive=True`; reporting no findings
from a scan that never ran is the same dangerous clean-target claim the sqlmap
and metasploit verdicts were fixed for.
"""

import pytest

from mcp_servers import zap_server
from mcp_servers.zap_server import ZapServer


def test_both_tools_are_registered_on_the_inner_server():
    srv = ZapServer()
    assert srv.mcp._tool_manager.get_tool("run_zap_baseline") is not None
    assert srv.mcp._tool_manager.get_tool("run_zap_active") is not None


@pytest.mark.asyncio
async def test_missing_api_key_never_contacts_zap(monkeypatch):
    async def _must_not_run(*args, **kwargs):
        raise AssertionError("network call made without an API key")

    monkeypatch.setattr(zap_server, "ZAP_API_KEY", "")
    srv = ZapServer()
    monkeypatch.setattr(srv, "_get", _must_not_run)
    monkeypatch.setattr(srv, "_action", _must_not_run)

    result = await srv._scan("http://juice_shop:3000/", active=False)

    assert result.inconclusive is True
    assert result.findings == []
    assert "ZAP_API_KEY" in result.raw_output


@pytest.mark.asyncio
async def test_baseline_spiders_and_runs_only_passive_scan(monkeypatch):
    calls = []

    async def fake_get(client, component, view, **params):
        calls.append((component, view))
        if (component, view) == ("core", "view/version"):
            return {"version": "2.15.0"}
        if (component, view) == ("spider", "view/status"):
            return {"status": "100"}
        if (component, view) == ("pscan", "view/recordsToScan"):
            return {"recordsToScan": "0"}
        if (component, view) == ("core", "view/alerts"):
            return {"alerts": [
                {"alert": "Missing Anti-clickjacking Header", "risk": "Medium",
                 "url": "http://juice_shop:3000/"},
                {"alert": "X-Content-Type-Options Header Missing",
                 "risk": "Low", "url": "http://juice_shop:3000/login"},
            ]}
        raise AssertionError(f"unexpected GET {component}/{view}")

    async def fake_action(client, component, action, **params):
        calls.append((component, action))
        if (component, action) == ("spider", "action/scan"):
            return {"scan": "1"}
        raise AssertionError(f"baseline must not start {component}/{action}")

    monkeypatch.setattr(zap_server, "ZAP_API_KEY", "test-key")
    srv = ZapServer()
    monkeypatch.setattr(srv, "_get", fake_get)
    monkeypatch.setattr(srv, "_action", fake_action)

    result = await srv._scan("http://juice_shop:3000/", active=False)

    assert result.inconclusive is False
    assert result.tool == "zap_baseline"
    assert ("spider", "action/scan") in calls
    assert not any("ascan" in call for call in calls)
    assert len(result.findings) == 2
    assert "Missing Anti-clickjacking Header" in result.findings[0]


@pytest.mark.asyncio
async def test_active_scan_runs_ascan_and_keeps_findings_unconfirmed(monkeypatch):
    calls = []

    async def fake_get(client, component, view, **params):
        calls.append((component, view))
        if (component, view) == ("core", "view/version"):
            return {"version": "2.15.0"}
        if (component, view) == ("spider", "view/status"):
            return {"status": "100"}
        if (component, view) == ("ascan", "view/status"):
            return {"status": "100"}
        if (component, view) == ("core", "view/alerts"):
            return {"alerts": [{"alert": "SQL Injection", "risk": "High",
                                 "url": "http://juice_shop:3000/", "param": "q"}]}
        raise AssertionError(f"unexpected GET {component}/{view}")

    async def fake_action(client, component, action, **params):
        calls.append((component, action))
        if (component, action) in (("spider", "action/scan"), ("ascan", "action/scan")):
            return {"scan": "1"}
        raise AssertionError(f"unexpected action {component}/{action}")

    monkeypatch.setattr(zap_server, "ZAP_API_KEY", "test-key")
    srv = ZapServer()
    monkeypatch.setattr(srv, "_get", fake_get)
    monkeypatch.setattr(srv, "_action", fake_action)

    result = await srv._scan("http://juice_shop:3000/", active=True)

    assert result.inconclusive is False
    assert result.tool == "zap_active"
    assert ("ascan", "action/scan") in calls
    assert result.findings == ["[High] SQL Injection at http://juice_shop:3000/ (parameter: q)"]
    assert "UNCONFIRMED" not in result.raw_output


@pytest.mark.asyncio
async def test_scan_failure_is_inconclusive_not_clean(monkeypatch):
    async def failing_get(client, component, view, **params):
        raise RuntimeError("daemon unreachable")

    monkeypatch.setattr(zap_server, "ZAP_API_KEY", "test-key")
    srv = ZapServer()
    monkeypatch.setattr(srv, "_get", failing_get)

    result = await srv._scan("http://juice_shop:3000/", active=False)

    assert result.inconclusive is True
    assert result.findings == []
    assert "daemon unreachable" in result.raw_output
