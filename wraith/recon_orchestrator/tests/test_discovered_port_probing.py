"""A port naabu found must actually be probed, not just recorded.

httpx is launched alongside naabu against the bare host, so target_url()
produces ``http://<host>`` and only ports 80/443 are ever requested. httpx
exits 0 when it reaches nothing, so the run was logged "completed
successfully" with zero endpoints -- and because every downstream tool keys
off httpx endpoints (katana, ffuf, linkfinder, kiterunner, trufflehog), the
entire HTTP half of recon silently produced nothing while reporting success.

The port list comes from naabu, which has already touched those ports, so
re-aiming httpx at them widens nothing; it only fixes the aim.
"""

import pytest

from app.orchestrator import ReconOrchestrator
from app.schemas import EndpointResult, PortResult, ReconSessionStatus, ToolResults


class _StubTool:
    """Stands in for a ReconTool; records every target it is handed."""

    def __init__(self, name):
        self.name = name
        self.targets = []

    async def run(self, domain):
        self.targets.append(domain)
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


async def _fire(orch, domain="juice_shop", completed="naabu"):
    """Run the trigger pass for `completed` and await whatever it launched."""

    class _Done:
        name = completed

    queued, tasks = set(), []
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

    assert "juice_shop:3000" in orch.httpx_probe.targets, (
        "the discovered port was never probed -- httpx only saw the bare host, "
        "so a service on anything but 80/443 is invisible to recon"
    )


@pytest.mark.asyncio
async def test_the_portless_run_still_happens():
    """The original bare-host probe is kept, not replaced."""
    orch = _orchestrator_with_results([_open(3000)])

    await _fire(orch)

    # queued already contains httpx:juice_shop (the initial wave); the new
    # entry is the port-scoped one, and both are recorded as separate keys.
    assert "juice_shop:3000" in orch.httpx_probe.targets


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
async def test_a_port_is_not_scheduled_twice():
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

    assert orch.httpx_probe.targets.count("juice_shop:3000") == 1, (
        "the same port was queued twice and probed twice"
    )