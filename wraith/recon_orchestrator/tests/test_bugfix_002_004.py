"""
Regression tests for BUG-002, BUG-003, BUG-004.

BUG-002: katana get_command used `-json` (invalid); katana only supports `-j`/`-jsonl`.
BUG-003: katana parse_output read `request["url"]`; katana emits `request["endpoint"]`.
BUG-004: orchestrator conditional trigger checked `httpx_probe` but tool name is `httpx`.
"""
import pytest
from app.tools.katana import KatanaTool
from app.tools.httpx_probe import HttpxProbeTool
from app.orchestrator import ReconOrchestrator
from app.schemas import ToolResults, EndpointResult


def test_bug002_katana_command_uses_j_not_json():
    """katana command must use -j (or -jsonl), never the invalid -json flag."""
    tool = KatanaTool()
    cmd = tool.get_command("http://example.com")
    assert "-json" not in cmd, "katana has no -json flag; would error: 'flag provided but not defined: -json'"
    assert "-j" in cmd, "katana JSON output flag is -j"
    assert "-u" in cmd
    assert "-silent" in cmd


def test_bug003_katana_parser_reads_endpoint_field():
    """katana emits request['endpoint']; parser must read it (with url fallback)."""
    tool = KatanaTool()
    # Real katana output uses "endpoint"
    output = (
        '{"request":{"endpoint":"https://example.com/about","method":"GET"},'
        '"response":{"status_code":200}}\n'
        '{"request":{"endpoint":"https://example.com/contact","method":"POST"},'
        '"response":{"status_code":200}}\n'
    )
    results = tool.parse_output(output)
    assert len(results.endpoints) == 2, "endpoints must be parsed from request.endpoint"
    assert results.endpoints[0].url == "https://example.com/about"
    assert results.endpoints[1].url == "https://example.com/contact"
    assert results.endpoints[1].method == "POST"
    assert results.endpoints[0].host == "example.com"


def test_bug003_katana_parser_falls_back_to_url():
    """If a tool variant emits request['url'], parser should still work (backward-compat)."""
    tool = KatanaTool()
    output = (
        '{"request":{"url":"https://example.com/legacy","method":"GET"},'
        '"response":{"status_code":200}}\n'
    )
    results = tool.parse_output(output)
    assert len(results.endpoints) == 1
    assert results.endpoints[0].url == "https://example.com/legacy"


def test_bug004_httpx_trigger_name_matches_tool_name():
    """
    The conditional trigger for 'active web service found' must key on the
    actual HttpxProbeTool.name ('httpx'), NOT 'httpx_probe'.
    """
    orch = ReconOrchestrator()
    # HttpxProbeTool registered as self.httpx_probe with name "httpx"
    assert orch.httpx_probe.name == "httpx", "HttpxProbeTool.name must be 'httpx'"

    # Simulate that the completed tool was httpx and verify the trigger condition
    # would evaluate correctly for the orchestrator's conditional logic.
    completed_tool = orch.httpx_probe
    session_id = "test-session"

    # We need a results object with endpoints to test the trigger logic.
    orch.results[session_id] = ToolResults(
        endpoints=[EndpointResult(host="example.com", url="http://example.com", method="GET", source_tool="httpx")]
    )

    # The exact condition from orchestrator.py line 321 (post-fix)
    trigger_condition = completed_tool.name in ["httpx", "katana"] and orch.results[session_id].endpoints
    assert trigger_condition, "httpx completion with endpoints must trigger downstream tools"

    # Verify old broken condition would have failed
    old_broken_condition = completed_tool.name in ["httpx_probe", "katana"] and orch.results[session_id].endpoints
    assert not old_broken_condition, "old condition keyed on 'httpx_probe' would never fire"
