import pytest
from unittest.mock import AsyncMock, patch
from mcp_servers.nmap_server import NmapServer, NmapScanType

SUCCESS = {"stdout": "", "stderr": "", "exit_code": 0, "success": True}


@pytest.mark.asyncio
async def test_nmap_scan_type_string_is_accepted():
    """Regression: run_nmap_scan must accept a plain string scan_type (default '-sV')
    without attempting to access '.value' on a str (was raising AttributeError)."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "scan_type": "-sV", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-p", "3000", "juice_shop:3000"]


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
    """Enum scan_type values (NmapScanType) must keep working."""
    server = NmapServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nmap_scan",
            {"target": "juice_shop:3000", "ports": "3000", "scan_type": NmapScanType.AGGRESSIVE, "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-A", "-p", "3000", "juice_shop:3000"]
