"""URL-form targets must survive the host:port split.

The executor normalises every destination to a URL, so the sandbox receives
`http://juice_shop:3000` far more often than `juice_shop:3000`. The old split
on the first colon returned `http` as the host and `//juice_shop:3000` as the
port; nmap refused that as an illegal port specification (Error #485) and the
proposal recorded a scan that never ran.
"""
import pytest
from unittest.mock import AsyncMock, patch
from mcp_servers.nmap_server import NmapServer

SUCCESS = {"stdout": "", "stderr": "", "exit_code": 0, "success": True}


@pytest.mark.asyncio
async def test_url_form_target_splits_into_host_and_port():
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "http://juice_shop:3000", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "3000", "juice_shop"], (
            f"URL-form target produced an illegal nmap command: {cmd}"
        )


@pytest.mark.asyncio
async def test_url_form_without_a_port_keeps_the_default_sweep():
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "http://juice_shop", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "1-1000", "juice_shop"]


def test_bare_host_port_and_bracketed_ipv6_still_split():
    server = NmapServer()

    assert server.split_host_port("juice_shop:3000") == ("juice_shop", "3000")
    assert server.split_host_port("juice_shop") == ("juice_shop", None)
    assert server.split_host_port("http://juice_shop:3000/api?x=1") == ("juice_shop", "3000")
    assert server.split_host_port("[::1]:3000") == ("[::1]", "3000")
    assert server.split_host_port("::1") == ("::1", None)
