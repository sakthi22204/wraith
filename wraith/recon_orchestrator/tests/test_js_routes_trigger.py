"""js_routes must actually be scheduled, not merely registered.

The tool is deliberately absent from the always-run base list: it is only worth
running once something has shown there is a JavaScript bundle to read. That
makes the conditional trigger the whole of its availability, so a registration
that is not also wired into the trigger is a tool that never runs.
"""
import asyncio

import pytest
from unittest.mock import patch

from app.orchestrator import ReconOrchestrator, _is_javascript_bundle
from app.schemas import EndpointResult, ReconSessionStatus, ToolResults
from app.tools.katana import KatanaTool
from app.tools.js_routes import JsRoutesTool


def orchestrator_with(*endpoints):
    orc = ReconOrchestrator()
    orc.sessions["s1"] = ReconSessionStatus(
        session_id="s1", investigation_id="inv-1", status="running",
        tool_statuses={}, progress=0.0,
    )
    orc.results["s1"] = ToolResults(endpoints=list(endpoints))
    return orc


async def trigger(orc):
    """Run the conditional triggers with tool execution stubbed out."""
    launched = []
    queued = set()
    running = []

    async def fake_run_tool(self, session_id, investigation_id, domain, tool):
        launched.append(tool.name)
        queued.add(f"{tool.name}:{domain}")
        return True

    with patch.object(ReconOrchestrator, "_run_tool", new=fake_run_tool):
        await orc._evaluate_conditional_triggers(
            "s1", "inv-1", "juice_shop:3000", KatanaTool(), queued, running
        )
        await asyncio.gather(*running)
    return launched


@pytest.mark.asyncio
async def test_js_routes_is_scheduled_when_a_bundle_is_discovered():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/main.js",
                       method="GET", source_tool="katana")
    )

    launched = await trigger(orc)

    assert "js_routes" in launched


@pytest.mark.asyncio
async def test_js_routes_is_scheduled_alongside_the_other_js_tools():
    """It extends the existing JavaScript trigger rather than replacing it."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/main.js",
                       method="GET", source_tool="katana")
    )

    launched = await trigger(orc)

    assert "linkfinder" in launched
    assert "secretfinder" in launched
    assert "js_routes" in launched


@pytest.mark.asyncio
async def test_js_routes_is_not_scheduled_without_a_bundle():
    """Reading HTML when there is no script to read would be a wasted fetch."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/",
                       method="GET", source_tool="httpx")
    )

    launched = await trigger(orc)

    assert "js_routes" not in launched


@pytest.mark.asyncio
async def test_js_routes_is_scheduled_once_however_many_bundles():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/main.js",
                       method="GET", source_tool="katana"),
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/polyfills.js",
                       method="GET", source_tool="katana"),
    )

    launched = await trigger(orc)

    assert launched.count("js_routes") == 1


def test_js_routes_is_absent_from_the_always_run_base_list():
    """It needs a bundle to be worth running, so it is triggered rather than
    listed. This pins that decision."""
    orc = ReconOrchestrator()

    assert orc.js_routes not in orc.tools
    assert isinstance(orc.js_routes, JsRoutesTool)


def test_js_routes_runs_in_process():
    """An in-process tool has no image, which is how ReconTool.run selects the
    in-process path."""
    assert JsRoutesTool().image is None


@pytest.mark.asyncio
async def test_base_run_dispatches_to_run_in_process():
    """The wiring: with no image, run() must reach the in-process method rather
    than trying to spawn a container that does not exist."""
    orc = orchestrator_with()

    class Stubbed(JsRoutesTool):
        def __init__(self):
            super().__init__()
            self.seen_domain = None

        async def run_in_process(self, domain):
            self.seen_domain = domain
            return ToolResults()

    stub = Stubbed()
    orc.js_routes = stub
    with patch("app.tools.base.docker_spawner") as spawner:
        await stub.run("juice_shop:3000")

    assert stub.seen_domain == "juice_shop:3000"
    spawner.spawn_container.assert_not_called()

class TestBundleDetection:
    """A versioned bundle is still a bundle.

    The trigger decided this with a whole-URL suffix test, so "/main.js?v=2"
    was not recognised. The failure is invisible -- the run proceeds normally
    and simply never reads the file that would have revealed the API surface --
    and a test using a bare "/main.js" path would keep passing throughout.
    """

    @pytest.mark.parametrize("url", [
        "http://juice_shop:3000/main.js",
        "http://juice_shop:3000/main.js?v=2",
        "http://juice_shop:3000/js/app.4f3a.js",
        "http://juice_shop:3000/main.js#fragment",
        "http://juice_shop:3000/MAIN.JS",
    ])
    def test_recognised(self, url):
        assert _is_javascript_bundle(url) is True

    @pytest.mark.parametrize("url", [
        "http://juice_shop:3000/main.js.map",
        "http://juice_shop:3000/rest/products/search?q=a.js",
        "http://juice_shop:3000/main.js/routes",
        "http://juice_shop:3000/",
        "",
    ])
    def test_not_recognised(self, url):
        assert _is_javascript_bundle(url) is False
