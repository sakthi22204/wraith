"""A scanner must not be run twice over the same URL set, nor overlapped with itself.

The trigger schedules a fresh nuclei pass every time the route set widens, which
is what makes a parameterised route reach the scanner at all. The same widening
that fixes coverage also stacks: katana, js_routes, ffuf and linkfinder each
start a pass while the previous one may still be running, and six concurrent
template runs against one local container took Juice Shop from 220MiB to its 6GiB
limit. A target at its memory ceiling stops answering, and a scanner that cannot
reach its target reports "0 findings" -- so the failure mode of running too many
scans at once is indistinguishable from a clean scan.

Both halves are pinned here: no overlapping runs, and no second run over URLs the
first one already covered.
"""
import asyncio

import pytest

from app.orchestrator import ReconOrchestrator
from app.schemas import EndpointResult, ReconSessionStatus, ToolResults
from app.tools.nuclei import NucleiTool


class _Recorder:
    """A real NucleiTool whose run() records instead of spawning a container."""

    def __init__(self, delay: float = 0.05):
        self.name = "nuclei"
        self.calls = []
        self.in_flight = 0
        self.max_in_flight = 0
        self.delay = delay

    async def run(self, domain, extra_urls=None):
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(self.delay)
            self.calls.append(tuple(extra_urls or ()))
            return ToolResults()
        finally:
            self.in_flight -= 1

    # Everything else -- _targets, the command, the flags -- is NucleiTool's, so
    # the dedupe path is exercised against the same URL set the tool would scan.
    _targets = NucleiTool._targets
    accepts_extra_urls = NucleiTool.accepts_extra_urls
    serialize_per_target = NucleiTool.serialize_per_target
    dedupe_scanned_urls = NucleiTool.dedupe_scanned_urls
    max_targets = NucleiTool.max_targets


def orchestrator_with(*urls, domain="juice_shop:3000"):
    orc = ReconOrchestrator()
    orc.nuclei = _Recorder()
    orc.sessions["s1"] = ReconSessionStatus(
        session_id="s1", investigation_id="i1", status="running",
        tool_statuses={}, progress=0.0,
    )
    orc.results["s1"] = ToolResults(
        endpoints=[
            EndpointResult(host="juice_shop", url=url, method="GET",
                           source_tool="httpx")
            for url in urls
        ]
    )

    async def _no_graph(investigation_id, results):
        return None

    orc._push_to_graph = _no_graph
    return orc


@pytest.mark.asyncio
async def test_overlapping_runs_of_the_same_tool_do_not_interleave():
    orc = orchestrator_with("http://juice_shop:3000/api")
    orc.nuclei.delay = 0.2

    await asyncio.gather(
        orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei),
        orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei),
    )

    assert orc.nuclei.max_in_flight == 1, (
        "two nuclei passes ran at once against the same target"
    )
    assert len(orc.nuclei.calls) == 1, (
        "the queued pass ran again over a URL set the first one already covered"
    )


@pytest.mark.asyncio
async def test_the_second_pass_over_an_unchanged_surface_is_a_noop():
    orc = orchestrator_with("http://juice_shop:3000/api")

    first = await orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei)
    second = await orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei)

    assert first is True and second is True
    assert len(orc.nuclei.calls) == 1, (
        "the same URL set was scanned twice in one session"
    )
    assert orc.sessions["s1"].tool_statuses["nuclei:juice_shop:3000"].value == "completed", (
        "a no-op pass must be recorded as completed, not left waiting"
    )
    assert any("nothing to scan" in line for line in orc.sessions["s1"].logs), (
        "the skipped pass left no trace in the session log"
    )


@pytest.mark.asyncio
async def test_a_widened_surface_is_scanned_again():
    orc = orchestrator_with("http://juice_shop:3000/api")

    await orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei)
    orc.results["s1"].endpoints.append(
        EndpointResult(host="juice_shop",
                       url="http://juice_shop:3000/rest/products/search?q=",
                       method="GET", source_tool="js_routes")
    )
    await orc._run_tool("s1", "i1", "juice_shop:3000", orc.nuclei)

    assert len(orc.nuclei.calls) == 2, "the new route never triggered a scan"
    assert "http://juice_shop:3000/rest/products/search?q=" in orc.nuclei.calls[1], (
        f"the second pass was not handed the new route: {orc.nuclei.calls[1]}"
    )


@pytest.mark.asyncio
async def test_different_spellings_of_the_same_host_share_one_lock():
    """`juice_shop` (base dispatch) and `http://juice_shop:3000` (triggered) are
    the same target; if they had separate locks they would run overlapping scans
    against the very container the lock exists to protect."""
    orc = orchestrator_with("http://juice_shop:3000/api")
    orc.nuclei.delay = 0.2

    await asyncio.gather(
        orc._run_tool("s1", "i1", "juice_shop", orc.nuclei),
        orc._run_tool("s1", "i1", "http://juice_shop:3000", orc.nuclei),
    )

    assert orc.nuclei.max_in_flight == 1, (
        "two scans of the same host ran at once under different domain spellings"
    )


@pytest.mark.asyncio
async def test_a_tool_that_does_not_declare_serialization_runs_unqueued():
    """The lock is opt-in: nothing else in the pipeline may start waiting on a
    lock it was never meant to hold."""
    orc = orchestrator_with("http://juice_shop:3000/api")
    plain = _Recorder()
    plain.serialize_per_target = False
    plain.dedupe_scanned_urls = False

    await asyncio.gather(
        orc._run_tool("s1", "i1", "juice_shop:3000", plain),
        orc._run_tool("s1", "i1", "juice_shop:3000", plain),
    )

    assert plain.max_in_flight == 2, (
        "a tool that opted out was serialized anyway"
    )


def test_the_severity_filter_is_gone():
    """`-severity low,medium,high,critical` dropped every `info` finding, and on
    this template set that is where the reportable matches live: tech, exposure
    and misc are all severity info, so the filtered run returned nothing while
    the unfiltered one returned matches."""
    cmd = NucleiTool().get_command("http://juice_shop:3000")

    assert "-severity" not in cmd, (
        "a severity filter is narrowing the report again"
    )
    assert "-rate-limit" in cmd, "the scan must stay rate limited"
    assert "-no-interactsh" in cmd, "OAST callbacks leak evidence off the host"
