import socket
import pytest
from unittest.mock import AsyncMock, patch

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

    def parse_output(self, output):
        return ToolResults()


@pytest.mark.asyncio
async def test_run_passes_extra_hosts_to_spawner(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda host: "172.18.0.3")
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await DummyTool().run("juice_shop:3000")
    mock_spawn.assert_awaited_once_with("dummy:latest", ["-host", "juice_shop:3000"], extra_hosts={"juice_shop": "172.18.0.3"})


@pytest.mark.asyncio
async def test_run_passes_none_extra_hosts_when_unresolvable(monkeypatch):
    def fail(host):
        raise socket.gaierror("no address")
    monkeypatch.setattr(socket, "gethostbyname", fail)
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await DummyTool().run("does-not-resolve.invalid")
    mock_spawn.assert_awaited_once_with("dummy:latest", ["-host", "does-not-resolve.invalid"], extra_hosts=None)
