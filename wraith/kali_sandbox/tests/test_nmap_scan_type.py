import pytest
from unittest.mock import AsyncMock, patch
from mcp_servers.nmap_server import NmapServer, NmapScanType

SUCCESS = {"stdout": "", "stderr": "", "exit_code": 0, "success": True}


@pytest.mark.asyncio
async def test_nmap_scan_type_string_is_accepted():
    """Regression: run_nmap_scan must accept a plain string scan_type (default '-sV')
    without attempting to access '.value' on a str (was raising AttributeError).
    The host:port target must be split for the CLI (host only)."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "scan_type": "-sV", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "3000", "juice_shop"]


@pytest.mark.asyncio
async def test_nmap_scan_type_default_string():
    """Default scan_type ('-sV') must not crash when not supplied."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd[1] == "-sV"


@pytest.mark.asyncio
async def test_nmap_scan_type_enum_still_supported():
    """Enum scan_type values (NmapScanType) must keep working, with host split."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "scan_type": NmapScanType.AGGRESSIVE, "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-A", "-p", "3000", "juice_shop"]


@pytest.mark.asyncio
async def test_nmap_host_port_split_embedded_port_used():
    """B2: target 'host:1234' must build '-p 1234 host' (host split from port,
    embedded port used when the caller did not override 'ports')."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "host:1234", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "1234", "host"]


@pytest.mark.asyncio
async def test_nmap_bare_host_default_ports_unchanged():
    """B2: bare target 'host' with default ports '1-1000' must build
    '-p 1-1000 host' unchanged."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "host", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "1-1000", "host"]


@pytest.mark.asyncio
async def test_nmap_result_preserves_original_target():
    """B2: the returned NmapResult must keep the original (unsplit) host:port
    target string for traceability, even though the CLI uses the split host."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        result = await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "caller": "exploit_agent"},
        )

        content_list, payload = result
        assert content_list[0].text
        assert payload["target"] == "juice_shop:3000"
