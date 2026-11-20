import asyncio
from types import SimpleNamespace

import pytest

import mcp_servers.native_host_server as native_mod

JOB = {
    "job_id": "job-1",
    "host_id": "host-one",
    "token": "marker-token-1234",
    "actions": ["load_probe", "log_verify"],
    "cleanup": True,
    "target_url": "https://host-one.native.invalid/.wraith/native",
    "callback_url": "http://oob.invalid/oob/token",
}


@pytest.fixture
def bridge_settings(monkeypatch):
    monkeypatch.setattr(native_mod, "settings", SimpleNamespace(
        REDIS_URL="",
        NATIVE_HOST_BRIDGE_URL="http://bridge.local:8010",
        NATIVE_HOST_BRIDGE_TOKEN="bridge-secret",
        NATIVE_HOST_PROBE_TIMEOUT=2.0,
    ))


class _Response:
    status_code = 200

    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


class _Client:
    captured = None

    def __init__(self, timeout=None):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, url, headers=None, json=None):
        type(self).captured = {
            "url": url, "headers": headers, "json": json, "timeout": self.timeout
        }
        return _Response({
            "evidence": {"load_probe": {"marker": "marker-token-1234"},
                         "secret": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
            "cleanup": {"removed": True},
            "target_url": JOB["target_url"],
        })


def _server():
    return native_mod.NativeHostServer()


def test_native_job_is_forwarded_unchanged(bridge_settings, monkeypatch):
    monkeypatch.setattr(native_mod.httpx, "AsyncClient", _Client)
    result = asyncio.run(_server().native_host_probe(
        target_url=JOB["target_url"], native_host_job=JOB
    ))
    sent = _Client.captured
    assert sent["url"] == "http://bridge.local:8010/jobs"
    assert sent["headers"]["X-Wraith-Bridge-Token"] == "bridge-secret"
    assert sent["json"] == JOB
    assert sent["timeout"] == 2.0
    assert result["status"] == "ok"
    assert result["evidence"]["load_probe"]["marker"] == "marker-token-1234"
    assert result["cleanup"] == {"removed": True}
    assert result["target_url"] == JOB["target_url"]
    assert "ghp_" not in str(result["evidence"])


def test_missing_bridge_configuration_returns_structured_error(monkeypatch):
    monkeypatch.setattr(native_mod, "settings", SimpleNamespace(
        NATIVE_HOST_BRIDGE_URL="",
        NATIVE_HOST_BRIDGE_TOKEN="bridge-secret",
        NATIVE_HOST_PROBE_TIMEOUT=1.0,
    ))
    result = asyncio.run(_server().native_host_probe(
        target_url=JOB["target_url"], native_host_job=JOB
    ))
    assert result["status"] == "error"
    assert result["evidence"] == {}
    assert result["cleanup"] == {}
    assert "bridge URL" in result["error"]


def test_missing_target_url_is_refused(bridge_settings):
    result = asyncio.run(_server().native_host_probe(native_host_job={}))
    assert result["status"] == "error"
    assert "target_url" in result["error"]


def test_non_200_bridge_response_returns_structured_error(bridge_settings, monkeypatch):
    class _FailingClient(_Client):
        async def post(self, url, headers=None, json=None):
            return SimpleNamespace(status_code=502)

    monkeypatch.setattr(native_mod.httpx, "AsyncClient", _FailingClient)
    result = asyncio.run(_server().native_host_probe(
        target_url=JOB["target_url"], native_host_job=JOB
    ))
    assert result["status"] == "error"
    assert "502" in result["error"]
    assert result["evidence"] == {}
