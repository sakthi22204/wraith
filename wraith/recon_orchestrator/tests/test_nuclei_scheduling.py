"""nuclei must run for local targets and for remote ones only on explicit opt-in.

Two regressions are pinned here.

1. It was unreachable for every target. nuclei was scheduled only through the
   grant-gated MCP wrappers the agent cannot use locally, so a Juice Shop E2E
   produced four header-level findings on an application with confirmed SQLi.

2. A first cut aimed it at the bare domain. Recon normalizes a target to `host`,
   so that probes port 80 while the app answers on 3000 -- a clean scan of
   nothing. It is aimed at the confirmed authority instead.

The ROE gate makes the distinction sharp: a remote host is template-scanned only
when the covering ROE allow rule is registered with ``allow_aggressive=True``.
Without that explicit authorization the scanner is never dispatched (the default
for every program), and with it the remote host scans exactly like a local one.
"""
import asyncio

import pytest

from app.orchestrator import ReconOrchestrator, _authority_of
from app.schemas import EndpointResult, ReconSessionStatus, ToolResults
from app.tools.nuclei import NucleiTool, SCAN_TAGS


class _StubTool:
    """Stands in for a ReconTool; records every target it is handed."""

    def __init__(self, name):
        self.name = name
        self.targets = []

    # The orchestrator only hands a tool its discovered endpoints when the tool
    # declares it can use them, so the stub has to declare it too -- otherwise it
    # silently records empty URL lists and every routing assertion passes for the
    # wrong reason.
    accepts_extra_urls = True

    async def run(self, domain, extra_urls=None):
        # The extra URLs are what a template is actually pointed at, so a test
        # that wants to know what got scanned has to see them recorded.
        self.targets.append((domain, tuple(extra_urls or ())))
        return ToolResults()


def orchestrator_with(*endpoints, domain="juice_shop:3000"):
    orc = ReconOrchestrator()
    orc.nuclei = _StubTool("nuclei")
    for name in ("httpx", "katana", "trufflehog", "gittools", "ffuf",
                 "linkfinder", "secretfinder", "js_routes", "kiterunner"):
        setattr(orc, name, _StubTool(name))
    orc.sessions["s1"] = ReconSessionStatus(
        session_id="s1", investigation_id="i1", status="running",
        tool_statuses={}, progress=0.0,
    )
    orc.results["s1"] = ToolResults(endpoints=list(endpoints))
    orc.domain = domain
    return orc


async def trigger(orc, domain="juice_shop:3000", completed="httpx", queued=None):
    """One trigger pass. Pass ``queued`` to continue a session across passes --
    a fresh set per call models a session that has forgotten what it already ran,
    which is not what the orchestrator does."""

    class _Done:
        name = completed

    queued = set() if queued is None else queued
    tasks = []
    await orc._evaluate_conditional_triggers(
        session_id="s1", investigation_id="i1", domain=domain,
        completed_tool=_Done(), queued_keys=queued, running_tasks=tasks,
    )
    for t in tasks:
        await t
    return queued


def test_nuclei_is_classified_aggressive_and_not_remote_safe():
    """The ROE gate keys off these two sets. If nuclei appears in the passive
    set, a real-world target gets template-scanned -- active traffic carrying
    injection payloads that no program here has authorized."""
    assert "nuclei" in ReconOrchestrator.AGGRESSIVE_TOOLS
    assert "nuclei" not in ReconOrchestrator.PASSIVE_REMOTE_TOOLS


@pytest.mark.asyncio
async def test_nuclei_runs_against_a_local_target():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="ffuf"),
    )

    launched = await trigger(orc)

    assert any(k.startswith("nuclei:") for k in launched), (
        "no vulnerability scanner was scheduled for a local target"
    )


@pytest.mark.asyncio
async def test_nuclei_is_not_scheduled_for_a_remote_target():
    orc = orchestrator_with(
        EndpointResult(host="example.com", url="https://example.com/api",
                       method="GET", source_tool="ffuf"),
        domain="example.com",
    )

    launched = await trigger(orc, domain="example.com")

    assert not any(k.startswith("nuclei:") for k in launched), (
        "nuclei was scheduled against a remote target"
    )


@pytest.mark.asyncio
async def test_nuclei_is_scheduled_for_a_remote_target_only_on_roe_opt_in():
    """allow_aggressive=True on the covering ROE rule opens the remote gate;
    the same dispatch code path runs once the session grants it."""
    orc = orchestrator_with(
        EndpointResult(host="example.com", url="https://example.com/api",
                       method="GET", source_tool="ffuf"),
        domain="example.com",
    )
    orc._aggressive_rules["s1"] = ["example.com"]

    launched = await trigger(orc, domain="example.com")

    assert any(k.startswith("nuclei:") for k in launched), (
        f"nuclei was not dispatched for a remote target with ROE opt-in: {sorted(launched)}"
    )


@pytest.mark.asyncio
async def test_remote_opt_in_does_not_leak_to_another_host():
    """The permission is per-host. A second, non-opted-in remote domain in the
    same session must stay gated."""
    orc = orchestrator_with(
        EndpointResult(host="example.com", url="https://example.com/api",
                       method="GET", source_tool="ffuf"),
        EndpointResult(host="partner.test", url="https://partner.test/api",
                       method="GET", source_tool="ffuf"),
        domain="example.com",
    )
    orc._aggressive_rules["s1"] = ["example.com"]

    opted = await trigger(orc, domain="example.com")
    assert any(k.startswith("nuclei:") for k in opted)

    gated = await trigger(orc, domain="partner.test")
    leaked = {
        k for k in gated
        if "partner.test" in k and k.split(":")[0] in ReconOrchestrator.AGGRESSIVE_TOOLS
    }
    assert not leaked, (
        f"aggressive permission leaked to a non-opted host: {sorted(leaked)}"
    )


@pytest.mark.asyncio
async def test_third_party_authorities_are_never_nuclei_targets():
    """The flipkart E2E scheduled a scan against login.microsoftonline.com
    because a crawler scraped an SSO link. Discovered endpoints include other
    people's hosts; a template scan of them is active traffic to a host no ROE
    rule covers, so the target set has to stay within the seed's own host."""
    orc = orchestrator_with(
        EndpointResult(host="www.flipkart.com", url="https://www.flipkart.com/",
                       method="GET", source_tool="katana"),
        EndpointResult(host="login.microsoftonline.com",
                       url="https://login.microsoftonline.com/common/oauth2/authorize?client_id=x",
                       method="GET", source_tool="katana"),
        domain="www.flipkart.com",
    )
    orc._aggressive_rules["s1"] = ["www.flipkart.com"]

    launched = await trigger(orc, domain="www.flipkart.com", completed="katana")

    assert any(k.startswith("nuclei:https://www.flipkart.com") for k in launched), (
        f"authorized host was not scanned: {sorted(launched)}"
    )
    assert not any("microsoftonline" in k for k in launched), (
        f"a third-party authority was handed to the scanner: {sorted(launched)}"
    )


@pytest.mark.asyncio
async def test_nuclei_is_aimed_at_the_port_that_answered():
    """Port 3000 is the whole point: aimed at the bare host it probes 80 and
    reports a clean scan of a service that was never contacted."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="ffuf"),
    )

    launched = await trigger(orc)

    assert any(k.startswith("nuclei:http://juice_shop:3000") for k in launched), (
        f"nuclei was not aimed at the confirmed authority: {sorted(launched)}"
    )


def test_authority_of_keeps_the_port_and_drops_the_path():
    assert _authority_of("http://juice_shop:3000/rest/products/search?q=") == \
        "http://juice_shop:3000"
    assert _authority_of("https://example.com/x") == "https://example.com"
    assert _authority_of("not-a-url") == ""
    assert _authority_of("") == ""


def test_discovered_endpoints_are_handed_to_the_scanner():
    """A template only fires against a URL it is pointed at. Given only the seed,
    an injection behind a query string on an unlinked route is never requested."""
    tool = NucleiTool()
    cmd = tool.get_command(
        "http://juice_shop:3000",
        ["http://juice_shop:3000/rest/products/search?q="],
    )
    targets = cmd[cmd.index("-u") + 1].split(",")
    assert "http://juice_shop:3000/rest/products/search?q=" in targets


def test_third_party_urls_from_a_discovered_bundle_are_excluded():
    """linkfinder extracts full URLs out of JavaScript, including other people's.
    A scanner handed those sends traffic outside the target's scope."""
    tool = NucleiTool()
    cmd = tool.get_command(
        "http://juice_shop:3000",
        ["https://cdn.example.com/lib.js", "http://juice_shop:3000/api"],
    )
    targets = cmd[cmd.index("-u") + 1].split(",")
    assert not any("cdn.example.com" in t for t in targets)
    assert "http://juice_shop:3000/api" in targets


def test_duplicate_endpoints_are_collapsed():
    tool = NucleiTool()
    cmd = tool.get_command(
        "http://juice_shop:3000",
        ["http://juice_shop:3000/api", "http://juice_shop:3000/api/"],
    )
    targets = cmd[cmd.index("-u") + 1].split(",")
    assert len(targets) == len(set(t.rstrip("/") for t in targets))


def test_without_discovered_endpoints_the_command_is_seed_only():
    """Byte-identical to the pre-change command when there is nothing extra."""
    tool = NucleiTool()
    assert tool.get_command("http://juice_shop:3000")[1] == "http://juice_shop:3000"


def test_scan_tags_include_the_vulnerability_templates():
    """An earlier revision passed only passive tags and scanned 0 matches against
    an injectable application. Narrowing this back breaks the tool silently."""
    for tag in ("sqli", "cve", "misconfig"):
        assert tag in SCAN_TAGS, f"{tag} missing from SCAN_TAGS"


def test_interactsh_is_disabled():
    """OAST templates register a callback domain and wait for a connection from
    a third-party server: an outbound request nobody asked for, carrying evidence
    off this host."""
    cmd = NucleiTool().get_command("http://juice_shop:3000")
    assert "-no-interactsh" in cmd


def test_bounded_by_a_real_nuclei_flag():
    """-crawl-duration is a katana flag. Passing it to nuclei makes it exit 1
    having scanned nothing, while the run still looks scheduled."""
    cmd = NucleiTool().get_command("http://juice_shop:3000")
    assert "-max-time" in cmd
    assert "-crawl-duration" not in cmd


def test_output_lines_are_only_the_findings():
    """Spawned containers merge stdout and stderr, so nuclei progress lines
    arrive interleaved with its results."""
    tool = NucleiTool()
    results = tool.parse_output(
        'time="2026-01-01T00:00:00" level=info msg="starting"\n'
        '{"template-id":"sqli","info":{"name":"SQL Injection",'
        '"severity":"high"},"matched-at":"http://juice_shop:3000/r?q=1"}\n'
        "not json at all\n",
        domain="juice_shop:3000",
    )
    assert len(results.endpoints) == 1
    assert results.endpoints[0].url == "http://juice_shop:3000/r?q=1"
    assert results.endpoints[0].host == "juice_shop"
    assert any("sqli" in n for n in results.notes)


def test_a_match_without_a_template_id_is_reported_not_silently_dropped():
    """A parser that discards results has to say so, or 'fuzzed and found
    nothing' is indistinguishable from 'never ran'."""
    tool = NucleiTool()
    results = tool.parse_output(
        '{"info":{"severity":"high"},"matched-at":"http://juice_shop:3000/r"}\n',
        domain="juice_shop:3000",
    )
    assert not results.endpoints
    assert results.notes and "template id" in results.notes[0]

# -- the scan has to happen after the routes are known -----------------------
#
# The trigger fires when httpx confirms the service. At that moment recon holds
# the root URL and nothing else: katana and js_routes have not reported yet, so
# /rest/products/search?q= -- the route carrying the injection -- does not exist
# as far as nuclei is concerned. Keying the run on the authority alone made the
# single early pass final for the session, so the scanner aimed at one URL and
# reported a clean run against an application with confirmed SQLi.


@pytest.mark.asyncio
async def test_a_later_widening_of_the_surface_reschedules_the_scan():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )

    queued = await trigger(orc, completed="httpx")
    first = set(queued)
    assert any(k.startswith("nuclei:") for k in first), (
        "nothing was scanned at all"
    )

    # js_routes reports the parameterised routes.
    orc.results["s1"].endpoints.append(
        EndpointResult(host="juice_shop",
                       url="http://juice_shop:3000/rest/products/search?q=",
                       method="GET", source_tool="js_routes")
    )
    second = await trigger(orc, completed="js_routes", queued=queued)

    new_keys = second - first
    assert any(k.startswith("nuclei:") for k in new_keys), (
        f"the widened surface did not reschedule nuclei: first={sorted(first)} "
        f"second={sorted(second)}"
    )


@pytest.mark.asyncio
async def test_the_rescheduled_run_is_handed_the_new_route():
    """Not just re-queued: the route reaches the scanner, so a template pointed
    at it is actually requested."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )
    queued = await trigger(orc, completed="httpx")

    orc.results["s1"].endpoints.append(
        EndpointResult(host="juice_shop",
                       url="http://juice_shop:3000/rest/products/search?q=",
                       method="GET", source_tool="js_routes")
    )
    await trigger(orc, completed="js_routes", queued=queued)

    handed = [u for _, urls in orc.nuclei.targets for u in urls]
    assert "http://juice_shop:3000/rest/products/search?q=" in handed, (
        f"the parameterised route never reached the scanner: {handed}"
    )


@pytest.mark.asyncio
async def test_an_unchanged_surface_is_not_scanned_again():
    """Re-queuing on every trigger pass would rerun the whole template set once
    per completed tool."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )
    queued = await trigger(orc, completed="httpx")
    before = len(orc.nuclei.targets)

    await trigger(orc, completed="ffuf", queued=queued)
    assert len(orc.nuclei.targets) == before, (
        f"the same surface was scanned {len(orc.nuclei.targets)} times"
    )


@pytest.mark.asyncio
async def test_a_new_authority_gets_its_own_scan():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
        EndpointResult(host="juice_shop", url="http://juice_shop:3001/api",
                       method="GET", source_tool="katana"),
    )
    launched = await trigger(orc, completed="httpx")
    assert any(k.startswith("nuclei:http://juice_shop:3000:") for k in launched)
    assert any(k.startswith("nuclei:http://juice_shop:3001:") for k in launched), (
        f"the second authority was never scanned: {sorted(launched)}"
    )


# -- passes coalesce instead of stacking --------------------------------------
#
# The trigger fires once per completed tool, and four tools can widen the
# surface while the pass they scheduled is still waiting on the per-target
# lock. Without coalescing each of those firings queued another full pass:
# the session's status table grew a ghost entry per firing (counted in the
# progress denominator for the whole run, never updated, swept to SKIPPED at
# the end), and the scans themselves stacked behind the lock one budget at a
# time. One pass per target at a time, always carrying the latest route set.


class _Fire:
    """A completed-tool name for the trigger, without a real tool behind it."""

    def __init__(self, name):
        self.name = name


async def _fire_raw(orc, completed, queued, tasks, domain="juice_shop:3000"):
    """One trigger pass, without awaiting what it launched."""
    await orc._evaluate_conditional_triggers(
        session_id="s1", investigation_id="i1", domain=domain,
        completed_tool=_Fire(completed), queued_keys=queued, running_tasks=tasks,
    )


@pytest.mark.asyncio
async def test_triggers_firing_while_a_pass_is_queued_schedule_one_run():
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )

    queued, tasks = set(), []
    await _fire_raw(orc, "httpx", queued, tasks)
    scheduled_after_first_fire = len(tasks)

    # katana reports a parameterised route before the queued pass has started.
    orc.results["s1"].endpoints.append(
        EndpointResult(host="juice_shop",
                       url="http://juice_shop:3000/rest/products/search?q=",
                       method="GET", source_tool="katana")
    )
    await _fire_raw(orc, "katana", queued, tasks)

    assert len(tasks) == scheduled_after_first_fire, (
        "a second nuclei pass was stacked behind one that had not even started"
    )
    # The route-count key is still recorded, so a *later* widening (after this
    # pass has run) schedules the next one rather than colliding with it.
    assert any(k.startswith("nuclei:http://juice_shop:3000:") for k in queued)

    for t in tasks:
        await t

    assert len(orc.nuclei.targets) == 1, (
        f"{len(orc.nuclei.targets)} nuclei runs happened for one queued pass"
    )
    handed = {u for _, urls in orc.nuclei.targets for u in urls}
    assert "http://juice_shop:3000/rest/products/search?q=" in handed, (
        "coalescing dropped the routes that widened while the pass was queued"
    )


@pytest.mark.asyncio
async def test_a_widening_during_a_running_pass_schedules_exactly_one_catchup():
    """A queued pass is folded into the pass that will run; a widening that
    arrives while a pass is RUNNING gets one catch-up -- and a third widening
    while that catch-up waits is folded into it, not scheduled again."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )

    started = asyncio.Event()
    release = asyncio.Event()

    class _BlockingNuclei:
        name = "nuclei"
        accepts_extra_urls = True
        # The lock is what makes "RUNNING" a real state here: without it the
        # catch-up would start immediately and the very window this test is
        # about (a pass running while new routes arrive) would not exist.
        serialize_per_target = True

        def __init__(self):
            self.targets = []

        async def run(self, domain, extra_urls=None):
            self.targets.append((domain, tuple(extra_urls or ())))
            started.set()
            await release.wait()
            return ToolResults()

    orc.nuclei = _BlockingNuclei()

    queued, tasks = set(), []
    await _fire_raw(orc, "httpx", queued, tasks)
    await asyncio.wait_for(started.wait(), timeout=5)
    # The pass is RUNNING now: its status is what gates rescheduling.

    def widen(url, source):
        orc.results["s1"].endpoints.append(
            EndpointResult(host="juice_shop", url=url, method="GET",
                           source_tool=source))

    widen("http://juice_shop:3000/rest/products/search?q=", "js_routes")
    before_catchup = len(tasks)
    await _fire_raw(orc, "js_routes", queued, tasks)
    assert len(tasks) == before_catchup + 1, (
        "a widening during a running pass must schedule one catch-up"
    )

    widen("http://juice_shop:3000/swagger", "ffuf")
    await _fire_raw(orc, "ffuf", queued, tasks)
    assert len(tasks) == before_catchup + 1, (
        "a third widening stacked a second catch-up behind the first"
    )

    release.set()
    for t in tasks:
        await t

    assert len(orc.nuclei.targets) == 2, (
        f"expected the original pass plus one catch-up, got {len(orc.nuclei.targets)}"
    )
    catchup_routes = set(orc.nuclei.targets[1][1])
    assert "http://juice_shop:3000/rest/products/search?q=" in catchup_routes
    assert "http://juice_shop:3000/swagger" in catchup_routes, (
        "the catch-up did not carry the routes that widened while it waited"
    )


@pytest.mark.asyncio
async def test_the_status_table_gets_one_unsuffixed_entry_per_scan_target():
    """queued_keys keeps the route count; the status table must not. A
    suffixed status entry is never touched again by _run_tool_body (which
    writes f"{tool}:{domain}"), so it stays WAITING forever, is reported as
    "never ran" at session end, and sits in the progress denominator -- the
    reason progress crawled below 100% on every multi-pass scan."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
    )

    await trigger(orc, completed="httpx")

    statuses = orc.sessions["s1"].tool_statuses
    assert statuses.get("nuclei:http://juice_shop:3000") is not None, (
        "the scan target has no status entry at all"
    )
    assert not any(k.startswith("nuclei:http://juice_shop:3000:") for k in statuses), (
        f"route-counted ghost entries in the status table: {sorted(statuses)}"
    )


def test_a_match_is_recorded_as_a_finding_not_only_an_endpoint():
    """nuclei matches reached the graph as Endpoints and notes, and the
    investigation's findings view came back empty on an application the scanner
    had flagged. A match is a Finding attached to the endpoint it was matched
    at, carrying the template, severity and title."""
    tool = NucleiTool()
    results = tool.parse_output(
        '{"template-id":"sqli","info":{"name":"SQL Injection",'
        '"severity":"high","description":"Boolean-based blind"},"matched-at":"http://juice_shop:3000/r?q=1"}\n',
        domain="juice_shop:3000",
    )
    assert len(results.findings) == 1
    finding = results.findings[0]
    assert finding.url == "http://juice_shop:3000/r?q=1"
    assert finding.host == "juice_shop"
    assert finding.method == "GET"
    assert finding.vuln_type == "sqli"
    assert finding.template_id == "sqli"
    assert finding.severity == "high"
    assert finding.title == "SQL Injection"
    assert finding.description == "Boolean-based blind"
    assert "sqli" in (finding.evidence or "")


@pytest.mark.asyncio
async def test_a_scan_pass_is_not_handed_routes_from_another_port():
    """A pass keyed on :3000 must scan :3000, not :3001.

    The original hang: a false endpoint on the bare host (port 80) created a
    `http://juice_shop` authority, and `_known_urls` matched only on hostname --
    so that dead-port pass was handed the entire :3000 surface and burned its
    budget timing out against port 80. Passes are now narrowed to the authority
    they were keyed on."""
    orc = orchestrator_with(
        EndpointResult(host="juice_shop", url="http://juice_shop:3000/api",
                       method="GET", source_tool="httpx"),
        EndpointResult(host="juice_shop", url="http://juice_shop:3001/admin",
                       method="GET", source_tool="httpx"),
    )

    await trigger(orc, completed="httpx")

    by_target = {}
    for target, urls in orc.nuclei.targets:
        by_target.setdefault(target, set()).update(urls)

    assert "http://juice_shop:3001/admin" not in by_target.get("http://juice_shop:3000", set())
    assert "http://juice_shop:3000/api" not in by_target.get("http://juice_shop:3001", set())
