"""How a container exited decides what its attempt means.

Three rules are pinned here.

1. A deadline stop is final: the scan ran, was cut off, and its partial
   output is kept and pushed. Retrying it spends another full budget on a
   wall clock that has just refused this one.
2. An OOM kill is final too: the same command against the same limit dies
   the same way. It is recorded as a failure -- there is no partial success
   to hand downstream -- and it is not retried.
3. The retry budget follows the tool's own wall clock. A tool that gets
   600s or more has already spent ten minutes on one attempt; a third
   attempt of that size is a session killer, not resilience.
"""
import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from app.docker_spawner import ToolDeadlineReached, ToolOOMKilled
from app.orchestrator import ReconOrchestrator
from app.schemas import (
    EndpointResult,
    HostResult,
    ReconSessionStatus,
    ToolResults,
    ToolStatus,
)
from app.tools.httpx_probe import HttpxProbeTool


def orchestrator_with():
    orc = ReconOrchestrator()
    orc.sessions["s1"] = ReconSessionStatus(
        session_id="s1", investigation_id="i1", status="running",
        tool_statuses={}, progress=0.0,
    )
    orc.results["s1"] = ToolResults()
    orc._push_to_graph = AsyncMock()
    return orc


class _AlwaysFails:
    """A tool whose container never produces a result."""

    accepts_extra_urls = False

    def __init__(self, name="httpx", timeout=None):
        self.name = name
        self.timeout = timeout
        self.calls = 0

    async def run(self, domain, **kwargs):
        self.calls += 1
        raise Exception("spawn failed")


class _Returns:
    """A tool that returns a pre-built result (flags included)."""

    accepts_extra_urls = False

    def __init__(self, results, name="httpx", timeout=None):
        self.name = name
        self.timeout = timeout
        self.results = results
        self.calls = 0

    async def run(self, domain, **kwargs):
        self.calls += 1
        return self.results


@pytest.mark.asyncio
async def test_a_long_budget_gets_only_two_attempts():
    orc = orchestrator_with()
    tool = _AlwaysFails(timeout=600)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        success = await orc._run_tool("s1", "i1", "juice_shop", tool)

    assert success is False
    assert tool.calls == 2, (
        f"a 600s-budget tool got {tool.calls} attempts; each one costs ten "
        "minutes of the session's wall clock"
    )
    assert orc.sessions["s1"].tool_statuses["httpx:juice_shop"] == ToolStatus.FAILED
    assert any("(Attempt 2/2)" in line for line in orc.sessions["s1"].logs), (
        "the log should show the budget-aware attempt count"
    )


@pytest.mark.asyncio
async def test_a_short_budget_keeps_the_third_attempt():
    orc = orchestrator_with()
    tool = _AlwaysFails(timeout=60)

    with patch("asyncio.sleep", new_callable=AsyncMock):
        success = await orc._run_tool("s1", "i1", "juice_shop", tool)

    assert success is False
    assert tool.calls == 3, "a cheap probe keeps the third retry"


@pytest.mark.asyncio
async def test_a_deadline_stop_is_final_keeps_results_and_pushes_them():
    orc = orchestrator_with()
    partial = ToolResults(
        endpoints=[EndpointResult(host="juice_shop",
                                  url="http://juice_shop/api", method="GET",
                                  source_tool="httpx")],
        timed_out=True,
        notes=["httpx was stopped at its wall-clock budget; partial output kept"],
    )
    tool = _Returns(partial, timeout=1800)

    success = await orc._run_tool("s1", "i1", "juice_shop", tool)

    assert tool.calls == 1, "a timed-out pass was retried against its budget"
    assert orc.sessions["s1"].tool_statuses["httpx:juice_shop"] == ToolStatus.TIMED_OUT
    # success=True: the partial findings exist, so the downstream triggers
    # that key off them must still fire for this tool.
    assert success is True
    # The partial output reached both the session and the graph.
    assert len(orc.results["s1"].endpoints) == 1
    orc._push_to_graph.assert_awaited_once()
    # And the session log says why the run stopped, not that it "completed".
    assert any("stopped at its budget" in line for line in orc.sessions["s1"].logs)
    assert not any("completed successfully" in line for line in orc.sessions["s1"].logs)


@pytest.mark.asyncio
async def test_an_oom_kill_is_final_and_marks_the_run_failed():
    orc = orchestrator_with()
    tool = _Returns(ToolResults(oom_killed=True), timeout=1800)

    success = await orc._run_tool("s1", "i1", "juice_shop", tool)

    assert tool.calls == 1, "an OOM-killed run was retried against its limit"
    assert orc.sessions["s1"].tool_statuses["httpx:juice_shop"] == ToolStatus.FAILED
    assert success is False
    assert any("OOM-killed" in line for line in orc.sessions["s1"].logs)


@pytest.mark.asyncio
async def test_a_successful_run_still_completes_and_pushes():
    orc = orchestrator_with()
    tool = _Returns(ToolResults(
        endpoints=[EndpointResult(host="juice_shop",
                                  url="http://juice_shop/", method="GET",
                                  source_tool="httpx")],
    ))

    success = await orc._run_tool("s1", "i1", "juice_shop", tool)

    assert success is True
    assert orc.sessions["s1"].tool_statuses["httpx:juice_shop"] == ToolStatus.COMPLETED
    orc._push_to_graph.assert_awaited_once()


# -- the spawner's abort exceptions become flags, not failures -----------------


@pytest.mark.asyncio
async def test_a_deadline_abort_from_the_spawner_becomes_partial_results():
    """ReconTool.run turns the typed abort into parsed output + flags, so the
    orchestrator can decide without inspecting logs -- and the container's
    flushed findings survive the stop."""
    tool = HttpxProbeTool()
    with patch("app.tools.base.docker_spawner.spawn_container",
               new_callable=AsyncMock) as mock_spawn:
        mock_spawn.side_effect = ToolDeadlineReached(
            "budget", logs='{"url":"http://juice_shop:3000/kept"}\n')

        results = await tool.run("juice_shop:3000")

    assert results.timed_out is True
    assert results.oom_killed is False
    assert [e.url for e in results.endpoints] == ["http://juice_shop:3000/kept"]
    assert any("stopped at its wall-clock budget" in n for n in results.notes)


@pytest.mark.asyncio
async def test_an_oom_abort_from_the_spawner_becomes_a_flagged_failure():
    tool = HttpxProbeTool()
    with patch("app.tools.base.docker_spawner.spawn_container",
               new_callable=AsyncMock) as mock_spawn:
        mock_spawn.side_effect = ToolOOMKilled("over limit", logs="")

        results = await tool.run("juice_shop:3000")

    assert results.oom_killed is True
    assert results.timed_out is False
    assert any("memory limit" in n for n in results.notes)


@pytest.mark.asyncio
async def test_force_extra_hands_the_batch_list_to_get_command_without_optin():
    """httpx does not opt in to extra URLs for ordinary runs -- its base
    command must stay byte-identical -- but a port batch forces them through."""
    tool = HttpxProbeTool()
    plain = tool.get_command("juice_shop")
    assert plain == ["-u", "http://juice_shop", "-json", "-silent"] or (
        plain[0] == "-u" and plain[1] == "http://juice_shop"
    ), f"the bare-host command changed: {plain}"

    with patch("app.tools.base.docker_spawner.spawn_container",
               new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await tool.run("juice_shop",
                       extra_urls=["http://juice_shop:3000", "http://juice_shop:8080"],
                       force_extra=True)

    cmd = mock_spawn.await_args.args[1]
    assert cmd[cmd.index("-u") + 1] == "http://juice_shop:3000,http://juice_shop:8080"

    # Without force_extra (and without accept), the extras are not seen.
    with patch("app.tools.base.docker_spawner.spawn_container",
               new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = ""
        await tool.run("juice_shop", extra_urls=["http://juice_shop:3000"])

    cmd = mock_spawn.await_args.args[1]
    assert cmd[cmd.index("-u") + 1] == "http://juice_shop", (
        "a tool that did not opt in saw the extra list anyway"
    )
