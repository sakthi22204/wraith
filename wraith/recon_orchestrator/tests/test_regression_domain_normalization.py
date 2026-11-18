import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from app.orchestrator import ReconOrchestrator
from app.schemas import ReconRequest, ToolResults, ToolStatus

@pytest.mark.asyncio
async def test_regression_domain_normalization():
    orchestrator = ReconOrchestrator()

    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["chyowe.com"]
    mock_graph.create_scan_session.return_value = {"id": "legacy_scan_id"}
    mock_graph.list_recon_sessions.return_value = []

    # Mock tool runs to succeed immediately with empty ToolResults
    for tool in orchestrator.tools:
        tool.run = AsyncMock(return_value=ToolResults())

    with patch("app.orchestrator.graph_client", mock_graph):
        request = ReconRequest(program_id="p1", domains=["https://chyowe.com"])
        res = await orchestrator.start_session(request)
        session_id = res["session_id"]

        # Wait for background task to complete
        timeout = 5
        start_time = asyncio.get_event_loop().time()
        while orchestrator.sessions[session_id].status in ["accepted", "running"]:
            await asyncio.sleep(0.1)
            if asyncio.get_event_loop().time() - start_time > timeout:
                break

        session = orchestrator.sessions[session_id]

        # Check there is exactly ONE tool_statuses entry per tool
        # e.g., "subfinder:chyowe.com", NOT "subfinder:https://chyowe.com"
        expected_keys = {f"{tool.name}:chyowe.com" for tool in orchestrator.tools}
        assert set(session.tool_statuses.keys()) == expected_keys

        # chyowe.com is a real-world target, so the ROE guard keeps the
        # aggressive scanners out of the base workflow. Passive tools run;
        # aggressive and cross-host tools are SKIPPED (not merely absent) so a
        # conditional trigger cannot later resurrect them.
        #
        # Scoped to the base workflow on purpose: tools that are only ever run
        # by a conditional trigger (nmap, ffuf, ...) are never scheduled here
        # at all, and a legacy catch-all closes them out as COMPLETED.
        base_tool_names = {
            "subfinder", "naabu", "httpx", "katana",
            "gau", "waybackurls",
        }
        # cloud_enum probes bucket names derived from the keyword, not the
        # authorized host, so it is deliberately outside PASSIVE_REMOTE_TOOLS.
        remote_skipped = {"cloud_enum"}
        for key, status in session.tool_statuses.items():
            tool_name = key.split(":")[0]
            if tool_name not in base_tool_names:
                continue
            if (tool_name in ReconOrchestrator.AGGRESSIVE_TOOLS
                    or tool_name in remote_skipped):
                assert status == ToolStatus.SKIPPED, f"{tool_name} should be ROE-skipped"
            else:
                assert status == ToolStatus.COMPLETED, f"{tool_name} should have run"

        # cloud_enum probes bucket names derived from the keyword (third-party
        # cloud infrastructure), so it is not a passive-remote tool and must be
        # closed out as SKIPPED rather than dispatched at a target the program
        # only authorized as an exact host.
        assert session.tool_statuses["cloud_enum:chyowe.com"] == ToolStatus.SKIPPED


@pytest.mark.asyncio
async def test_local_target_skips_external_archive_tools():
    orchestrator = ReconOrchestrator()
    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["juice_shop:3000"]
    mock_graph.create_scan_session.return_value = {"id": "scan-1"}
    mock_graph.list_recon_sessions.return_value = []
    mock_graph.update_recon_session.return_value = None

    for tool in orchestrator.tools:
        tool.run = AsyncMock(return_value=ToolResults())

    with patch("app.orchestrator.graph_client", mock_graph):
        result = await orchestrator.start_session(
            ReconRequest(program_id="local", domains=["juice_shop:3000"])
        )
        session_id = result["session_id"]
        while orchestrator.sessions[session_id].status in ["accepted", "running"]:
            await asyncio.sleep(0.05)

    statuses = orchestrator.sessions[session_id].tool_statuses
    assert statuses["gau:juice_shop:3000"] == ToolStatus.SKIPPED
    assert statuses["waybackurls:juice_shop:3000"] == ToolStatus.SKIPPED
    assert statuses["cloud_enum:juice_shop:3000"] == ToolStatus.SKIPPED


@pytest.mark.asyncio
async def test_port_qualified_target_is_in_scope_of_a_bare_host_rule():
    """The graph stores a bare host in ``scope_domains`` (scope_host strips the
    port), while a local investigation may name ``juice_shop:3000`` -- the port
    the app answers on. The runner authorizes on the destination host, so the
    bare rule already covers every port; recon's door check has to ask the same
    question or it rejects a fully authorized target before any tool runs.
    This is the exact 400 the Juice Shop E2E hit."""
    orchestrator = ReconOrchestrator()
    mock_graph = AsyncMock()
    mock_graph.get_program_scope.return_value = ["juice_shop"]
    mock_graph.create_scan_session.return_value = {"id": "scan-1"}
    mock_graph.list_recon_sessions.return_value = []
    mock_graph.update_recon_session.return_value = None

    for tool in orchestrator.tools:
        tool.run = AsyncMock(return_value=ToolResults())

    with patch("app.orchestrator.graph_client", mock_graph):
        result = await orchestrator.start_session(
            ReconRequest(program_id="local", domains=["juice_shop:3000"])
        )
        session_id = result["session_id"]

    # Accepted, and the port is preserved in the status keys: it names the
    # service to scan, not just the host.
    assert orchestrator.sessions[session_id].status in ("accepted", "running", "completed")
    assert any(k.endswith(":juice_shop:3000") for k in orchestrator.sessions[session_id].tool_statuses)
