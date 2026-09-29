import pytest
from unittest.mock import AsyncMock, patch
from mcp_servers.nuclei_server import NucleiServer, NucleiTemplateCategory

SUCCESS = {"stdout": "", "stderr": "", "exit_code": 0, "success": True}


@pytest.mark.asyncio
async def test_nuclei_category_string_is_accepted():
    """Regression: run_nuclei_scan must accept a plain string category (as sent by
    the exploit agent LLM) without attempting to access '.value' on a str (was
    raising AttributeError and failing every agent-driven nuclei execution)."""
    server = NucleiServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nuclei_scan",
            {"target": "http://juice_shop:3000", "category": "vulnerabilities", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nuclei", "-u", "http://juice_shop:3000", "-jsonl", "-silent", "-dc", "-c", "15", "-timeout", "5", "-t", "http/vulnerabilities"]


@pytest.mark.asyncio
async def test_nuclei_category_default_string():
    """Default category ('default') must not crash and must not append -t."""
    server = NucleiServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nuclei_scan",
            {"target": "http://juice_shop:3000", "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nuclei", "-u", "http://juice_shop:3000", "-jsonl", "-silent", "-dc", "-c", "15", "-timeout", "5"]


@pytest.mark.asyncio
async def test_nuclei_category_enum_still_supported():
    """Enum category values (NucleiTemplateCategory) must keep working."""
    server = NucleiServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        await server.mcp.call_tool(
            "run_nuclei_scan",
            {"target": "http://juice_shop:3000", "category": NucleiTemplateCategory.CVES, "caller": "exploit_agent"},
        )

        cmd = mock_run.call_args[0][0]
        assert cmd == ["nuclei", "-u", "http://juice_shop:3000", "-jsonl", "-silent", "-dc", "-c", "15", "-timeout", "5", "-t", "http/cves"]

@pytest.mark.asyncio
async def test_nuclei_category_invalid_is_graceful():
    """Invalid categories (e.g. LLM-invented 'wordpress') must not crash and
    must not shell out to nuclei with a bogus template path."""
    server = NucleiServer()

    with patch.object(server, "run_tool", new=AsyncMock(return_value=SUCCESS)) as mock_run:
        result = await server.mcp.call_tool(
            "run_nuclei_scan",
            {"target": "http://juice_shop:3000", "category": "wordpress", "caller": "exploit_agent"},
        )

        mock_run.assert_not_awaited()
        text = str(result)
        assert "Invalid category" in text
        assert "wordpress" in text
