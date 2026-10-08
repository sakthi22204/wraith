import socket
import pytest
from unittest.mock import ANY, AsyncMock, patch

from app.tools.base import ReconTool, host_from_domain, resolve_extra_hosts
from app.schemas import ToolResults


def test_host_from_domain_strips_scheme_port_path():
    assert host_from_domain("juice_shop:3000") == "juice_shop"
    assert host_from_domain("http://juice_shop:3000") == "juice_shop"
    assert host_from_domain("https://example.com/path") == "example.com"
    assert host_from_domain("example.com") == "example.com"
    assert host_from_domain("sub.example.com") == "sub.example.com"


def test_resolve_extra_hosts_returns_none_for_ip_literal():
    assert resolve_extra_hosts("172.18.0.3") is None


def test_resolve_extra_hosts_resolves_internal_name(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "172.18.0.3")
    assert resolve_extra_hosts("juice_shop:3000") == {"juice_shop": "172.18.0.3"}


def test_resolve_extra_hosts_returns_none_when_unresolvable(monkeypatch):
    def fail(host):
        raise socket.gaierror("no address")
    monkeypatch.setattr(socket, "gethostbyname", fail)
    assert resolve_extra_hosts("does-not-resolve.invalid") is None


class DummyTool(ReconTool):
    def __init__(self):
        super().__init__(name="dummy", image="dummy:latest")

    def get_command(self, domain):
        return ["-host", domain]

    def parse_output(self, output, domain=""):
        # The domain is part of the parser contract: several tools report bare
        # paths and cannot produce an addressable endpoint without it.
        self.seen_domain = domain
        return ToolResults()


@pytest.mark.asyncio
async def test_run_passes_extra_hosts_to_spawner(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "172.18.0.3")
    # The proxy contributes its own extra_hosts entry when RECON_PROXY_URL is
    # set, so asserting the whole dict would make this test depend on ambient
    # .env state. This is about the *tool's* target being resolvable; the proxy
    # merge is pinned in test_proxy.py.
    monkeypatch.setattr("app.tools.base.proxy_extra_hosts", lambda: {})
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await DummyTool().run("juice_shop:3000")
    mock_spawn.assert_awaited_once_with(
        "dummy:latest", ["-host", "juice_shop:3000"],
        timeout=ANY, extra_hosts={"juice_shop": "172.18.0.3"},
        environment=ANY, volumes=ANY, mem_limit=None, cpu_quota=None,
    )


@pytest.mark.asyncio
async def test_run_merges_the_proxy_host_into_extra_hosts(monkeypatch):
    """Go tools resolve single-label names via /etc/hosts, not Docker DNS.

    With interception on, the proxy hostname has to reach the container too or
    httpx/katana cannot reach the sidecar even though the tool's own target
    resolved fine.
    """
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "172.18.0.3")
    monkeypatch.setattr("app.tools.base.proxy_extra_hosts", lambda: {"mitmproxy_sidecar": "172.19.0.16"})
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await DummyTool().run("juice_shop:3000")
    _, kwargs = mock_spawn.call_args
    assert kwargs["extra_hosts"] == {
        "juice_shop": "172.18.0.3",
        "mitmproxy_sidecar": "172.19.0.16",
    }


@pytest.mark.asyncio
async def test_run_passes_none_extra_hosts_when_unresolvable(monkeypatch):
    def fail(host):
        raise socket.gaierror("no address")
    monkeypatch.setattr(socket, "gethostbyname", fail)
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await DummyTool().run("does-not-resolve.invalid")
    # An unresolvable host yields no extra_hosts, but the call still carries the
    # tool timeout and the (empty) proxy environment/volume configuration.
    mock_spawn.assert_awaited_once_with(
        "dummy:latest", ["-host", "does-not-resolve.invalid"],
        timeout=ANY, extra_hosts=None, environment=ANY, volumes=ANY,
        mem_limit=None, cpu_quota=None,
    )


@pytest.mark.asyncio
async def test_run_hands_the_parser_the_domain_it_was_invoked_with():
    """The tool's target is the only place a bare path can get its host.

    Dropping it here silently removed every fuzzed/crawled path from the rest
    of the pipeline, which is not something a per-tool unit test would catch.
    """
    tool = DummyTool()
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await tool.run("juice_shop:3000")
    assert tool.seen_domain == "juice_shop:3000"
