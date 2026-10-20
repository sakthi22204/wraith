"""A port naabu found must actually be probed, not just recorded.

httpx is launched alongside naabu against the bare host, so target_url()
produces ``http://<host>`` and only ports 80/443 are ever requested. httpx
exits 0 when it reaches nothing, so the run was logged "completed
successfully" with zero endpoints -- and because every downstream tool keys
off httpx endpoints (katana, ffuf, linkfinder, kiterunner, trufflehog), the
entire HTTP half of recon silently produced nothing while reporting success.

The port list comes from naabu, which has already touched those ports, so
re-aiming httpx at them widens nothing; it only fixes the aim. One batched
pass covers every discovered port -- httpx takes a comma-joined -u list --
instead of one container per port paying image startup for a single probe.
"""

import pytest

from app.orchestrator import ReconOrchestrator
from app.schemas import EndpointResult, PortResult, ReconSessionStatus, ToolResults


class _StubTool:
    """Stands in for a ReconTool; records every target it is handed.

    Both halves matter: the domain the run was invoked on, and the extra URL
    list that is the whole point of the port batch.
    """

    def __init__(self, name):
        self.name = name
        self.targets = []
        self.extra_url_batches = []

    async def run(self, domain, extra_urls=None, force_extra=False):
        self.targets.append(domain)
        if extra_urls:
            self.extra_url_batches.append(tuple(extra_urls))
        return ToolResults()


def _orchestrator_with_results(ports):
    orch = ReconOrchestrator()
    orch.httpx_probe = _StubTool("httpx")
    orch.sessions["s1"] = ReconSessionStatus(
        session_id="s1", investigation_id="i1", status="running",
        tool_statuses={}, progress=0.0,
    )
    # _evaluate_conditional_triggers reads accumulated results from here.
    orch.results["s1"] = ToolResults(ports=ports)
    return orch


def _open(port, host="juice_shop", protocol="tcp", state="open"):
    return PortResult(host=host, number=port, protocol=protocol,
                      state=state, source_tool="naabu")


async def _fire(orch, domain="juice_shop", completed="naabu", queued=None):
    """Run the trigger pass for `completed` and await whatever it launched."""

    class _Done:
        name = completed

    queued = set() if queued is None else queued
    tasks = []
    await orch._evaluate_conditional_triggers(
        session_id="s1", investigation_id="i1", domain=domain,
        completed_tool=_Done(), queued_keys=queued, running_tasks=tasks,
    )
    for t in tasks:
        await t
    return queued


@pytest.mark.asyncio
async def test_an_open_port_is_probed_and_not_merely_recorded():
    orch = _orchestrator_with_results([_open(3000)])

    await _fire(orch)

    probed = [u for batch in orch.httpx_probe.extra_url_batches for u in batch]
    assert "http://juice_shop:3000" in probed, (
        "the discovered port was never probed -- httpx only saw the bare host, "
        "so a service on anything but 80/443 is invisible to recon"
    )


@pytest.mark.asyncio
async def test_the_port_batch_runs_once_on_the_bare_host():
    """The batch is one run against the seed domain carrying every port URL;
    the original bare-host probe at session start is kept, not replaced."""
    orch = _orchestrator_with_results([_open(3000), _open(8080)])

    await _fire(orch)

    assert orch.httpx_probe.targets == ["juice_shop"], (
        "the port batch must run once, on the seed domain"
    )
    assert orch.httpx_probe.extra_url_batches == [
        ("http://juice_shop:3000", "http://juice_shop:8080")
    ], "the discovered ports must reach httpx as one comma-joined batch"


@pytest.mark.asyncio
async def test_a_discovered_port_unlocks_the_downstream_cascade():
    """Endpoints on a non-default port must trigger the dependent tools."""
    orch = _orchestrator_with_results([_open(3000)])
    orch.results["s1"].endpoints = [
        EndpointResult(host="juice_shop", url="http://juice_shop:3000",
                       method="GET", source_tool="httpx")
    ]
    ffuf = _StubTool("ffuf")
    orch.ffuf = ffuf
    orch.nuclei = _StubTool("nuclei")

    await _fire(orch, completed="httpx")

    assert ffuf.targets, (
        "httpx found a live web service but nothing was scheduled off it"
    )


@pytest.mark.asyncio
async def test_closed_and_udp_ports_are_not_probed():
    orch = _orchestrator_with_results([
        _open(3000, state="closed"),
        _open(53, protocol="udp"),
    ])

    await _fire(orch)

    assert orch.httpx_probe.targets == [], (
        "closed and UDP ports must not become HTTP probe targets"
    )


@pytest.mark.asyncio
async def test_the_port_batch_is_not_scheduled_twice():
    orch = _orchestrator_with_results([_open(3000)])

    class _Done:
        name = "naabu"

    queued, tasks = set(), []
    for _ in range(2):
        await orch._evaluate_conditional_triggers(
            session_id="s1", investigation_id="i1", domain="juice_shop",
            completed_tool=_Done(), queued_keys=queued, running_tasks=tasks,
        )
        for t in tasks:
            await t

    assert len(orch.httpx_probe.targets) == 1, (
        f"the port batch was queued {len(orch.httpx_probe.targets)} times and "
        "probed more than once"
    )
    assert orch.httpx_probe.extra_url_batches == [
        ("http://juice_shop:3000",)
    ], "the same port was probed twice"
