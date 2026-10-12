import asyncio
import ipaddress
import re
import uuid
from datetime import datetime
from typing import Dict, List
from urllib.parse import urlparse, urlsplit
from fastapi import HTTPException
from .schemas import ReconRequest, ReconSessionStatus, ToolStatus, ToolResults, HostResult
from .tools.subfinder import SubfinderTool
from .tools.httpx_probe import HttpxProbeTool
from .tools.katana import KatanaTool
from .tools.naabu import NaabuTool
from .tools.dnsx import DnsxTool
from .tools.nmap import NmapTool
from .tools.tlsx import TlsxTool
from .tools.nuclei import NucleiTool
from .tools.gau import GauTool
from .tools.waybackurls import WaybackurlsTool
from .tools.ffuf import FfufTool
from .tools.kiterunner import KiterunnerTool
from .tools.linkfinder import LinkfinderTool
from .tools.secretfinder import SecretfinderTool
from .tools.trufflehog import TrufflehogTool
from .tools.gittools import GittoolsTool
from .tools.wpscan import WpscanTool
from .tools.cloud_enum import CloudEnumTool
from .tools.js_routes import JsRoutesTool
from .tools.base import host_from_domain, target_url
from .graph_client import graph_client
from .scope_sync import ScopeReconciliationError, fetch_roe_rules, reconcile
from .config import settings


def _authority_of(url: str) -> str:
    """`scheme://host:port` for a URL, or "" if it has no scheme.

    Used to aim a scan at the port something actually answered on. A tool given
    only a bare hostname probes port 80, so a service reachable solely on 3000 is
    never touched -- which is how a scanner can report a clean run against a
    target that is listening elsewhere.
    """
    if not url or "://" not in url:
        return ""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ""
    if not parsed.hostname:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def _is_static_asset(url: str) -> bool:
    """Does this URL point at a file served as a file, not a route?"""
    path = urlsplit(url).path.lower()
    return path.endswith((
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp",
    ))


def _is_javascript_bundle(url: str) -> bool:
    """Does this URL point at a JavaScript bundle?

    Judged on the path, with the query string and fragment removed. Bundles are
    routinely served cache-busted ("/main.js?v=2", "/app.4f3a.js"), so a whole-URL
    suffix test misses them -- and a miss here is invisible, because the run
    simply proceeds without reading the one file that would have revealed the
    API surface.
    """
    try:
        path = urlparse(url or "").path
    except ValueError:
        return False
    return path.lower().endswith(".js")

class ReconOrchestrator:
    # Tools that send high-rate / brute-force traffic or aggressive scans
    # (port scans, fuzzing, crawlers, CMS scanners). A program's rules of
    # engagement typically cap request rate and forbid aggressive scanning, so
    # these are never run against real-world (non-local) targets.
    # nuclei runs vulnerability templates, which is active traffic against the
    # target. It is aggressive by that measure and stays out of the remote set
    # below, so a remote run marks it SKIPPED rather than dispatching it.
    AGGRESSIVE_TOOLS = {"naabu", "katana", "nmap", "ffuf", "kiterunner", "wpscan",
                        "gittools", "nuclei"}

    # Passive / light-touch tools that are safe against remote targets.
    PASSIVE_REMOTE_TOOLS = {
        "subfinder", "httpx", "gau", "waybackurls", "cloud_enum",
        "dnsx", "tlsx", "linkfinder", "secretfinder", "trufflehog",
    }

    def __init__(self):
        self.sessions: Dict[str, ReconSessionStatus] = {}
        self.results: Dict[str, ToolResults] = {}

        # Tools definitions
        self.subfinder = SubfinderTool()
        self.httpx_probe = HttpxProbeTool()
        self.katana = KatanaTool()
        self.naabu = NaabuTool()
        self.dnsx = DnsxTool()
        self.nmap = NmapTool()
        self.tlsx = TlsxTool()
        self.nuclei = NucleiTool()
        self.gau = GauTool()
        self.waybackurls = WaybackurlsTool()
        self.ffuf = FfufTool()
        self.kiterunner = KiterunnerTool()
        self.linkfinder = LinkfinderTool()
        self.secretfinder = SecretfinderTool()
        self.trufflehog = TrufflehogTool()
        self.gittools = GittoolsTool()
        self.wpscan = WpscanTool()
        self.cloud_enum = CloudEnumTool()
        # Not in self.tools: it has no place in the always-run base set, because
        # it is only worth running once something has shown there is a JavaScript
        # bundle to read. It is scheduled by the conditional trigger instead.
        self.js_routes = JsRoutesTool()

        # Fully implemented real tools activated and wired up
        self.tools = [
            self.subfinder, self.httpx_probe, self.katana, self.naabu,
            self.dnsx, self.nmap, self.tlsx, self.gau, self.waybackurls,
            self.ffuf, self.nuclei,
            self.kiterunner,
            self.linkfinder,
            self.secretfinder,
            self.trufflehog,
            self.gittools,
            self.wpscan, self.cloud_enum
        ]

        self.semaphore = asyncio.Semaphore(10)  # Concurrency limit
        self.running_tasks: Dict[str, List[asyncio.Task]] = {}

        # Per-session ROE aggressive permission: the ROE rule patterns under
        # which a remote target may be scanned with aggressive tools (vuln
        # templates, port scans, brute-force crawlers). Empty for a session
        # means no remote target is aggressive-exempt, which keeps the ROE gate
        # closed for every program that has not explicitly opted in. See
        # _aggressive_allowed.
        self._aggressive_rules: Dict[str, List[str]] = {}

        # Per-session, per-domain serialization for tools that declare
        # `serialize_per_target`, plus the URL sets those tools have already
        # covered this session. See _run_tool: a scanner that fans out across
        # every discovered route is safe once and dangerous when several passes
        # overlap, and the trigger that schedules those passes has no way to
        # know another one is still running.
        self._target_locks: Dict[str, asyncio.Lock] = {}
        self._scanned_urls: Dict[str, set] = {}

    @staticmethod
    def _is_local_target(domain: str) -> bool:
        host = domain.rsplit(":", 1)[0]
        if host == "localhost" or "_" in host or host.endswith(".local"):
            return True
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

    def _aggressive_allowed(self, session_id: str, domain: str) -> bool:
        """May aggressive tools target ``domain`` this session?

        Local targets always qualify -- the platform owns those hosts. A remote
        (real-world) target qualifies only when an ROE allow rule that covers it
        was registered with ``allow_aggressive=True``. Every other remote target
        keeps the hard ROE gate closed, so an allow rule is opt-in per host and
        never blankets a whole program.
        """
        if self._is_local_target(domain):
            return True
        patterns = self._aggressive_rules.get(session_id) or []
        if not patterns:
            return False
        norm = self.normalize_domain(host_from_domain(domain) or domain)
        return self._scope_matches_any(norm, patterns)

    async def run_session(self, session_id: str, investigation_id: str, domains: List[str]):
        session = self.sessions[session_id]
        session.status = "running"
        session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Automatic recon workflow started.")

        try:
            await graph_client.update_recon_session(session_id, "running")
        except Exception as e:
            print(f"Failed to update recon session {session_id} to running: {e}")

        graph_session_id = None
        # Register session in graph_db
        try:
            graph_session = await graph_client.create_scan_session(investigation_id)
            graph_session_id = graph_session["id"]
        except Exception as e:
            print(f"Failed to register session in graph_db for session {session_id}: {e}")

        # Core base tools run initially.
        # dnsx and tlsx belong here: both are passive (DNS queries and a single
        # TLS handshake) and both are declared remote-safe in
        # PASSIVE_REMOTE_TOOLS, but they were absent from this list, so every
        # remote session left them WAITING and the graph received no hosts and
        # no ports at all. JS-dependent tools are intentionally not listed --
        # they are scheduled from the bundles that httpx/js_routes find.
        base_tools = [
            self.subfinder,
            self.naabu,
            self.httpx_probe,
            self.katana,
            self.gau,
            self.waybackurls,
            self.cloud_enum,
            self.dnsx,
            self.tlsx,
        ]
  

        queued_keys = set()
        running_tasks = []

        # Initialize WAITING status for all self.tools on domains (test expectations)
        for domain in domains:
            for tool in self.tools:
                tool_key = f"{tool.name}:{domain}"
                session.tool_statuses[tool_key] = ToolStatus.WAITING

        # Archive and cloud-asset tools cannot produce meaningful data for a
        # Docker-local service and can wait on external providers.
        for domain in domains:
            aggressive_ok = self._aggressive_allowed(session_id, domain)
            domain_base_tools = base_tools
            if self._is_local_target(domain):
                skipped_tools = {self.gau, self.waybackurls, self.cloud_enum}
                domain_base_tools = [tool for tool in base_tools if tool not in skipped_tools]
                for tool in skipped_tools:
                    tool_key = f"{tool.name}:{domain}"
                    session.tool_statuses[tool_key] = ToolStatus.SKIPPED
                    session.logs.append(
                        f"[{datetime.utcnow().strftime('%H:%M:%S')}] Skipping {tool.name} for Docker-local target {domain}."
                    )
            elif aggressive_ok:
                # Real-world target with an explicit ROE opt-in
                # (allow_aggressive=True covers this host). The full base set
                # runs, including naabu and katana; the permission is per-host,
                # so nothing about this branch is implicit.
                domain_base_tools = base_tools
            else:
                # Real-world target: honor the program's rules of engagement.
                # Only passive / light-touch tools are scheduled; aggressive
                # scanners are marked SKIPPED so conditional triggers can never
                # resurrect them later in the session.
                domain_base_tools = [tool for tool in base_tools if tool.name in self.PASSIVE_REMOTE_TOOLS]
                for tool in base_tools:
                    if tool.name in self.AGGRESSIVE_TOOLS or tool.name not in self.PASSIVE_REMOTE_TOOLS:
                        tool_key = f"{tool.name}:{domain}"
                        session.tool_statuses[tool_key] = ToolStatus.SKIPPED
                        session.logs.append(
                            f"[{datetime.utcnow().strftime('%H:%M:%S')}] Skipping {tool.name} for remote target {domain} (ROE: aggressive scanning / brute-force traffic not permitted)."
                        )
            for tool in domain_base_tools:
                tool_key = f"{tool.name}:{domain}"
                queued_keys.add(tool_key)

        # Launch base tools and track wrapper tasks
        for domain in domains:
            domain_base_tools = [
                tool for tool in base_tools
                if session.tool_statuses[f"{tool.name}:{domain}"] != ToolStatus.SKIPPED
            ]
            for tool in domain_base_tools:
                t = asyncio.create_task(self._run_tool(session_id, investigation_id, domain, tool))

                async def wait_and_trigger(task, t_tool, d_domain):
                    try:
                        success = await task
                        if success:
                            # Trigger appropriate downstream tools based on dynamic conditions!
                            await self._evaluate_conditional_triggers(session_id, investigation_id, d_domain, t_tool, queued_keys, running_tasks)
                        return success
                    except Exception as e:
                        print(f"Task {t_tool.name} failed: {e}")
                        return False

                wrapper_task = asyncio.create_task(wait_and_trigger(t, tool, domain))
                running_tasks.append(wrapper_task)

        # Wait until all queued tasks (including dynamically added ones) are complete
        while True:
            unfinished = [t for t in running_tasks if not t.done()]
            if not unfinished:
                break
            await asyncio.sleep(0.5)

        # Once all tools are completed, finish the session
        any_failed = False
        all_failed = True
        for t in running_tasks:
            try:
                res = t.result()
                if res is False:
                    any_failed = True
                else:
                    all_failed = False
            except Exception:
                any_failed = True

        if all_failed and len(running_tasks) > 0:
            session.status = "failed"
        elif any_failed:
            session.status = "partial"
        else:
            session.status = "completed"

        # Tools still WAITING never ran: they were neither in the base set nor
        # triggered. Reporting them as COMPLETED claimed work that did not
        # happen -- an nmap or ffuf that was withheld by the ROE gate showed up
        # as a successful scan, which is the same false confidence as grading a
        # blocked request as a confirmed finding. They are recorded as SKIPPED,
        # with a log line naming the tool, so the session report says what
        # actually executed.
        never_ran = [k for k, v in session.tool_statuses.items() if v == ToolStatus.WAITING]
        for k in never_ran:
            session.tool_statuses[k] = ToolStatus.SKIPPED
            session.logs.append(
                f"[{datetime.utcnow().strftime('%H:%M:%S')}] {k} was not scheduled "
                f"and did not run; recorded as skipped."
            )

        session.progress = 100.0
        session.current_tool = None
        session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Automatic recon workflow finished with status: {session.status}")

        if graph_session_id:
            try:
                await graph_client.update_scan_session(graph_session_id, session.status)
            except Exception as e:
                print(f"Failed to update session status in graph_db: {e}")

        # Final update to ReconSession in graph_db
        max_attempts = 3
        delay = 2.0
        tool_results = {
            "hosts_found": len(self.results.get(session_id, ToolResults()).hosts),
            "ports_found": len(self.results.get(session_id, ToolResults()).ports),
            "endpoints_found": len(self.results.get(session_id, ToolResults()).endpoints),
            "tool_statuses": {k: v.value for k, v in session.tool_statuses.items()},
            "logs": session.logs
        }

        for attempt in range(1, max_attempts + 1):
            try:
                await graph_client.update_recon_session(session_id, session.status, tool_results)
                print(f"Successfully updated recon session {session_id} in graph_db on attempt {attempt}")
                break
            except Exception as e:
                if attempt == max_attempts:
                    import logging
                    logging.getLogger("recon_orchestrator").error(
                        f"CRITICAL ERROR: Failed to update recon session {session_id} in graph_db after {max_attempts} attempts: {e}"
                    )
                else:
                    print(f"Failed to update recon session {session_id} in graph_db on attempt {attempt}/{max_attempts}: {e}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                    delay *= 2

    def _known_urls(self, session_id: str, domain: str) -> List[str]:
        """Discovered endpoint URLs on this domain, for tools that aim at them.

        Filtered to the seed's own host. linkfinder and js_routes extract full
        URLs out of JavaScript bundles, including third-party ones, and a
        scanner handed those would send traffic outside the target's scope.
        """
        seed_host = (host_from_domain(target_url(domain)) or "").lower()
        out: List[str] = []
        for ep in self.results.get(session_id, ToolResults()).endpoints:
            url = (ep.url or "").split("#", 1)[0]
            if not url.lower().startswith(("http://", "https://")):
                continue
            if seed_host and (host_from_domain(url) or "").lower() != seed_host:
                continue
            out.append(url)
        return out

    async def _evaluate_conditional_triggers(self, session_id: str, investigation_id: str, domain: str, completed_tool, queued_keys: set, running_tasks: list):
        session = self.sessions[session_id]
        results = self.results.get(session_id, ToolResults())
        remote = not self._is_local_target(domain)
        # The ROE gate keys off this, not off `remote`: a remote host the
        # program explicitly opted into (allow_aggressive=True) scans identical
        # to a local one, and a local one is never gated.
        aggressive_ok = self._aggressive_allowed(session_id, domain)

        async def launch_tool(tool, domain):
            tool_key = f"{tool.name}:{domain}"
            t = asyncio.create_task(self._run_tool(session_id, investigation_id, domain, tool))
            try:
                success = await t
                if success:
                    await self._evaluate_conditional_triggers(session_id, investigation_id, domain, tool, queued_keys, running_tasks)
                return success
            except Exception as e:
                print(f"Task {tool_key} failed: {e}")
                return False

        # 1. WordPress detection (Trigger WPScan)
        wordpress_detected = False
        for endpoint in results.endpoints:
            url_lower = endpoint.url.lower()
            if "wp-content" in url_lower or "wp-includes" in url_lower or "wp-json" in url_lower:
                wordpress_detected = True
                break
        if wordpress_detected and aggressive_ok:
            wpscan_key = f"wpscan:{domain}"
            if wpscan_key not in queued_keys:
                queued_keys.add(wpscan_key)
                session.tool_statuses[wpscan_key] = ToolStatus.WAITING
                session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] WordPress detected on {domain}. Scheduling WPScan.")
                task_launch = asyncio.create_task(launch_tool(self.wpscan, domain))
                running_tasks.append(task_launch)

        # 2. JavaScript found (Trigger LinkFinder and SecretFinder)
        js_detected = False
        for endpoint in results.endpoints:
            # The path decides, not the whole URL. A bundle served as
            # "/main.js?v=2" does not end in ".js", and real ones are
            # versioned -- so a suffix test silently skipped the exact files
            # worth reading while still passing a test that used a bare path.
            if _is_javascript_bundle(endpoint.url):
                js_detected = True
                break
        if js_detected:
            # js_routes reads the bundle the target already serves. LinkFinder
            # and SecretFinder read secrets and links; js_routes reads the route
            # table, which is the one thing that shows up in a single-page app
            # and nowhere else. Without it an SPA recon finds its own shell and
            # static assets and never its API.
            for tool in [self.linkfinder, self.secretfinder, self.js_routes]:
                tool_key = f"{tool.name}:{domain}"
                if tool_key not in queued_keys:
                    queued_keys.add(tool_key)
                    session.tool_statuses[tool_key] = ToolStatus.WAITING
                    session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] JavaScript file(s) detected. Scheduling {tool.name}.")
                    task_launch = asyncio.create_task(launch_tool(tool, domain))
                    running_tasks.append(task_launch)

        # 3. API endpoints found (Trigger Kiterunner)
        api_detected = False
        for endpoint in results.endpoints:
            url_lower = endpoint.url.lower()
            if "/api" in url_lower or "/v1" in url_lower or "/v2" in url_lower or "swagger" in url_lower:
                api_detected = True
                break
        if api_detected and aggressive_ok:
            kiterunner_key = f"kiterunner:{domain}"
            if kiterunner_key not in queued_keys:
                queued_keys.add(kiterunner_key)
                session.tool_statuses[kiterunner_key] = ToolStatus.WAITING
                session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] API endpoint(s) detected. Scheduling Kiterunner.")
                task_launch = asyncio.create_task(launch_tool(self.kiterunner, domain))
                running_tasks.append(task_launch)

        # 4. Host discovery (Trigger dnsx)
        if completed_tool.name == "subfinder" and results.hosts:
            dnsx_key = f"dnsx:{domain}"
            if dnsx_key not in queued_keys:
                queued_keys.add(dnsx_key)
                session.tool_statuses[dnsx_key] = ToolStatus.WAITING
                session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Hosts discovered. Scheduling dnsx resolution.")
                task_launch = asyncio.create_task(launch_tool(self.dnsx, domain))
                running_tasks.append(task_launch)

        # 5. Discovered open ports (Trigger Nmap, tlsx and port-scoped HTTpx)
        if completed_tool.name == "naabu" and results.ports and aggressive_ok:
            # Trigger Nmap
            nmap_key = f"nmap:{domain}"
            if nmap_key not in queued_keys:
                queued_keys.add(nmap_key)
                session.tool_statuses[nmap_key] = ToolStatus.WAITING
                session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Open ports discovered. Scheduling Nmap scan.")
                task_launch = asyncio.create_task(launch_tool(self.nmap, domain))
                running_tasks.append(task_launch)

            # Trigger HTTpx against the ports naabu actually found.
            #
            # httpx ran concurrently with naabu, on the bare host, so it probed
            # port 80/443 and nothing else. A service on 3000 (or 8000, or 9200)
            # was invisible to it, and because httpx exits 0 when it reaches
            # nothing the run was logged as "completed successfully" with zero
            # endpoints -- so every downstream trigger that keys off httpx
            # (katana, ffuf, linkfinder, kiterunner) never fired either. The
            # whole HTTP half of recon was silently blind to non-default ports.
            #
            # The port list is naabu's, so this cannot widen the scan beyond
            # what the port scan already touched; it only re-aims the probe.
            http_ports = sorted({
                p.number for p in results.ports
                if p.state == "open" and p.protocol == "tcp"
            })
            for port in http_ports:
                port_target = f"{domain}:{port}"
                port_key = f"httpx:{port_target}"
                if port_key in queued_keys:
                    continue
                queued_keys.add(port_key)
                session.tool_statuses[port_key] = ToolStatus.WAITING
                session.logs.append(
                    f"[{datetime.utcnow().strftime('%H:%M:%S')}] "
                    f"Open port {port} on {domain}. Scheduling httpx on {port_target}."
                )
                task_launch = asyncio.create_task(launch_tool(self.httpx_probe, port_target))
                running_tasks.append(task_launch)

            # Trigger tlsx on TLS ports
            has_tls_ports = any(p.number in [443, 8443] or p.protocol == "https" for p in results.ports)
            if has_tls_ports:
                tlsx_key = f"tlsx:{domain}"
                if tlsx_key not in queued_keys:
                    queued_keys.add(tlsx_key)
                    session.tool_statuses[tlsx_key] = ToolStatus.WAITING
                    session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] TLS ports discovered. Scheduling tlsx.")
                    task_launch = asyncio.create_task(launch_tool(self.tlsx, domain))
                    running_tasks.append(task_launch)

        # 7. HTTP surface confirmed (Trigger nuclei vulnerability templates).
        #
        # Gated on aggressive allowance, not on the passive/aggressive sets: a
        # template run sends crafted payloads, which is exactly the traffic a
        # program's rules of engagement govern. Without this, the Juice Shop E2E
        # produced four header-level findings on an application with confirmed
        # SQLi, because the only vulnerability scanner in the pipeline was
        # reachable only through grant-gated MCP tools the agent could not use
        # here.
        if aggressive_ok:
            # Scope nuclei at the authorities httpx/katana actually confirmed, not
            # at the bare domain. Recon normalizes a target to `host`, so a
            # service on 3000 (or 8080, or 9200) is invisible to a scan aimed at
            # port 80 -- which is where the Juice Shop SQLi lives, on 3000.
            #
            # The URL set is `_known_urls`, which is filtered to the seed's own
            # host -- never the session-wide endpoint list. On a real site the
            # crawlers scrape genuinely third-party URLs (SSO, CDNs, analytics,
            # OAuth providers), and handing those to a template scanner is active
            # traffic to a host no ROE rule covers. The Juice Shop E2E never hit
            # this because every endpoint stays on the local box; the flipkart
            # E2E scheduled `nuclei:https://login.microsoftonline.com:443`
            # against a page that only linked there.
            #
            # Static assets are not a scan surface. A bundle is not an API route,
            # and handing nuclei the crawl root and every .js file as a scan
            # target spends its budget re-fetching files that were just read.
            known = self._known_urls(session_id, domain)
            known_scan = sorted({
                u.split("#", 1)[0] for u in known
                if not _is_javascript_bundle(u) and not _is_static_asset(u)
            })
            vuln_targets = sorted({_authority_of(u) for u in known_scan} - {""})
            # Scan routes, not just the authority. nuclei is handed the discovered
            # endpoints as targets, and that list is the whole point: an injection
            # behind a query string on a route nothing links to
            # (/rest/products/search?q=) is never requested by a scan aimed at the
            # homepage alone.
            #
            # Which is why the route count is part of the key. This block first runs
            # when httpx confirms the service, and at that point recon holds the
            # root URL and nothing else -- katana and js_routes have not reported
            # yet, so the parameterised routes that make this worth running do not
            # exist. Keying on the authority alone marked it done for the whole
            # session, and the Juice Shop E2E scanned one URL and reported a clean
            # run against an application with confirmed SQLi. Keying on the route
            # count lets each later tool that widens the surface schedule a pass.
            scan_routes = {
                target: sorted({
                    u for u in known_scan
                    if _authority_of(u) == target
                })
                for target in vuln_targets
            }
            for target in vuln_targets:
                for tool in [self.nuclei]:
                    route_count = len(scan_routes.get(target) or [])
                    tool_key = f"{tool.name}:{target}:{route_count}"
                    if tool_key in queued_keys:
                        continue
                    queued_keys.add(tool_key)
                    session.tool_statuses[tool_key] = ToolStatus.WAITING
                    session.logs.append(
                        f"[{datetime.utcnow().strftime('%H:%M:%S')}] "
                        f"HTTP surface confirmed on {target}. Scheduling {tool.name} "
                        f"over {route_count} route(s) "
                        f"({'local target' if not remote else 'remote target (ROE allow_aggressive)'})."
                    )
                    task_launch = asyncio.create_task(launch_tool(tool, target))
                    running_tasks.append(task_launch)
  
        # 6. Active HTTP web service found (Trigger GitTools, ffuf, TruffleHog)
        if completed_tool.name in ["httpx", "katana"] and results.endpoints:
            triggered_tools = [self.trufflehog, self.gittools, self.ffuf]
            for tool in triggered_tools:
                # ffuf (content enumeration) and gittools are active/brute-force
                # checks; never run them against real-world targets unless a
                # program has explicitly opted that host in.
                if not aggressive_ok and tool.name in self.AGGRESSIVE_TOOLS:
                    continue
                tool_key = f"{tool.name}:{domain}"
                if tool_key not in queued_keys:
                    queued_keys.add(tool_key)
                    session.tool_statuses[tool_key] = ToolStatus.WAITING
                    session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Active web endpoints found. Scheduling {tool.name}.")
                    task_launch = asyncio.create_task(launch_tool(tool, domain))
                    running_tasks.append(task_launch)

    async def _run_tool(self, session_id: str, investigation_id: str, domain: str, tool):
        run_key = f"{session_id}:{domain}"
        if not getattr(tool, "serialize_per_target", False):
            return await self._run_tool_body(session_id, investigation_id, domain, tool, run_key)

        # A scanner that fans out across every discovered URL is safe once and
        # unsafe when several passes overlap. The conditional trigger schedules
        # a fresh pass every time the route set widens, so katana, js_routes,
        # ffuf and linkfinder can each start one while the previous scan is
        # still running: six concurrent nuclei processes against one local
        # container took Juice Shop from 220MiB to its 6GiB limit, and once the
        # target stopped answering every scan in flight reported "0 findings" --
        # a scanner that cannot reach its target reports a clean bill of health.
        #
        # Key the lock on the host, not the domain string: `juice_shop` (base
        # dispatch) and `http://juice_shop:3000` (triggered, port-scoped) are the
        # same box and the same scan surface, and separately-locked runs would
        # overlap against the very container whose memory we are protecting.
        lock_key = f"{session_id}:{(host_from_domain(domain) or domain).lower()}"
        lock = self._target_locks.setdefault(lock_key, asyncio.Lock())
        async with lock:
            return await self._run_tool_body(session_id, investigation_id, domain, tool, run_key)

    def _planned_targets(self, tool, session_id: str, domain: str):
        """The URLs an incremental pass should still cover, or None if it does not dedupe.

        Returns only what has not been scanned yet this session, so a rescheduler
        hands the scanner exactly the routes that widened the surface instead of
        re-running the whole template set over every URL seen so far.
        """
        if not getattr(tool, "dedupe_scanned_urls", False) or not hasattr(tool, "_targets"):
            return None
        extra = self._known_urls(session_id, domain) if getattr(tool, "accepts_extra_urls", False) else None
        already = self._scanned_urls.get(f"{session_id}:{domain}", set())
        return [u for u in tool._targets(domain, extra) if u not in already]

    async def _run_tool_body(self, session_id: str, investigation_id: str, domain: str, tool, run_key: str):
        session = self.sessions[session_id]
        tool_key = f"{tool.name}:{domain}"
        planned = self._planned_targets(tool, session_id, domain)

        # Same session, same target, nothing new to look at: the earlier run(s)
        # already covered every URL this one would scan. Re-running it burns the
        # tool's whole budget to rediscover a result we have. COMPLETED, not
        # SKIPPED, because the work it was scheduled for was done -- the log says
        # so, so "scanned and clean" stays distinguishable from "never ran".
        if planned is not None and not planned:
            timestamp = datetime.utcnow().strftime("%H:%M:%S")
            session.logs.append(
                f"[{timestamp}] {tool.name} on {domain}: no new targets since the "
                f"earlier pass this session; nothing to scan."
            )
            session.tool_statuses[tool_key] = ToolStatus.COMPLETED
            return True
        extra_urls = planned if planned is not None else None

        async with self.semaphore:
            session.current_tool = tool.name
            max_attempts = 3
            success = False

            for attempt in range(1, max_attempts + 1):
                timestamp = datetime.utcnow().strftime("%H:%M:%S")
                if attempt == 1:
                    session.tool_statuses[tool_key] = ToolStatus.RUNNING
                    session.logs.append(f"[{timestamp}] Starting {tool.name} on {domain} (Attempt {attempt}/{max_attempts})")
                else:
                    session.tool_statuses[tool_key] = ToolStatus.RETRYING
                    session.logs.append(f"[{timestamp}] Retrying {tool.name} on {domain} (Attempt {attempt}/{max_attempts})")

                try:
                    # Hand the tool the endpoints discovered so far on this
                    # domain, so a scanner can aim at real routes instead of
                    # only at the seed URL. Only tools declaring
                    # accepts_extra_urls get them; everything else is called
                    # exactly as before, so no other tool's command changes.
                    # A deduplicated tool gets only the URLs it has not seen
                    # yet, so a rescan after the surface widened costs a scan of
                    # the new routes, not a replay of the whole template set.
                    if getattr(tool, "accepts_extra_urls", False):
                        results = await tool.run(
                            domain,
                            extra_urls=(self._known_urls(session_id, domain)
                                        if extra_urls is None else extra_urls))
                    else:
                        results = await tool.run(domain)
                    timestamp_done = datetime.utcnow().strftime("%H:%M:%S")
                    session.logs.append(f"[{timestamp_done}] {tool.name} completed successfully on {domain}")

                    await self._push_to_graph(investigation_id, results)

                    # Store results for the session
                    if session_id not in self.results:
                        self.results[session_id] = ToolResults()
                    self.results[session_id].hosts.extend(results.hosts)
                    self.results[session_id].ports.extend(results.ports)
                    self.results[session_id].endpoints.extend(results.endpoints)
                    for note in getattr(results, "notes", []) or []:
                        # A parser that drops results has to say so, or
                        # "fuzzed and found nothing" is indistinguishable from
                        # "never ran".
                        session.logs.append(
                            f"[{datetime.utcnow().strftime('%H:%M:%S')}] "
                            f"{tool.name} on {domain}: {note}"
                        )

                    session.tool_statuses[tool_key] = ToolStatus.COMPLETED
                    if planned:
                        self._scanned_urls.setdefault(run_key, set()).update(planned)
                    success = True
                    break
                except asyncio.TimeoutError:
                    timestamp_err = datetime.utcnow().strftime("%H:%M:%S")
                    session.logs.append(f"[{timestamp_err}] {tool.name} timed out on {domain} (Attempt {attempt}/{max_attempts})")
                    if attempt < max_attempts:
                        await asyncio.sleep(1) # wait 1s before retry
                except Exception as e:
                    timestamp_err = datetime.utcnow().strftime("%H:%M:%S")
                    session.logs.append(f"[{timestamp_err}] {tool.name} failed on {domain}: {e} (Attempt {attempt}/{max_attempts})")
                    if attempt < max_attempts:
                        await asyncio.sleep(1) # wait 1s before retry

            if not success:
                timestamp_failed = datetime.utcnow().strftime("%H:%M:%S")
                session.logs.append(f"[{timestamp_failed}] {tool.name} failed on {domain} after {max_attempts} attempts.")
                session.tool_statuses[tool_key] = ToolStatus.FAILED

            # Reset current tool if this was the last running one
            if session.current_tool == tool.name:
                other_running = [k.split(":")[0] for k, v in session.tool_statuses.items() if v in [ToolStatus.RUNNING, ToolStatus.RETRYING] and k != tool_key]
                session.current_tool = other_running[0] if other_running else None

            # Update overall progress
            completed = sum(1 for s in session.tool_statuses.values()
                           if s in [ToolStatus.COMPLETED, ToolStatus.SKIPPED, ToolStatus.TIMED_OUT, ToolStatus.FAILED])
            session.progress = (completed / len(session.tool_statuses)) * 100.0

            return success

    async def _push_to_graph(self, investigation_id: str, results: ToolResults):
        # A single recon run yields tens of thousands of endpoints spread over a
        # few hundred distinct hosts. Upserting the host inside the per-endpoint
        # loop cost one Cypher round-trip per endpoint -- ~46k redundant calls on
        # the toom.de run, which dominated wall-clock at roughly 50 minutes.
        # upsert_host is idempotent on host value (it posts only {"value": ...}),
        # so resolving each distinct host once and reusing its node id is exactly
        # equivalent, just without the repeat traffic.
        host_ids: Dict[str, str] = {}

        async def host_id_for(host: str, source_tool: str) -> str:
            if host not in host_ids:
                host_obj = await graph_client.upsert_host(
                    investigation_id, HostResult(value=host, source_tool=source_tool))
                host_ids[host] = host_obj["id"]
            return host_ids[host]

        for host in results.hosts:
            await host_id_for(host.value, host.source_tool)

        for port in results.ports:
            hid = await host_id_for(port.host, port.source_tool)
            await graph_client.upsert_port(hid, port)

        for endpoint in results.endpoints:
            hid = await host_id_for(endpoint.host, endpoint.source_tool)
            await graph_client.upsert_endpoint(hid, endpoint)

    async def cancel_session(self, session_id: str):
        if session_id in self.running_tasks:
            for task in self.running_tasks[session_id]:
                task.cancel()
            del self.running_tasks[session_id]

        if session_id in self.sessions:
            self.sessions[session_id].status = "cancelled"

    def normalize_domain(self, domain: str) -> str:
        """Strip scheme and trailing slashes from domain."""
        d = domain.lower().strip()
        if "://" in d:
            d = d.split("://")[1]
        return d.split("/")[0]

    # Multi-part public suffixes (registrable domain = last two labels without
    # these). Keep the common ones so apex-vs-subdomain scope matching is safe.
    MULTI_PART_SUFFIXES = {        "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "co.jp",
        "co.in", "net.in", "org.in", "com.br", "co.za", "com.cn", "com.hk",
        "com.tr", "com.my", "com.sg", "com.ph", "co.kr", "com.tw", "com.eg",
        "com.sa", "com.pk", "com.ng", "com.gh", "co.ke", "com.ar", "com.co",
    }

    def registrable_domain(self, domain: str) -> str:
        """Return the registrable (apex) domain, e.g. a.b.example.com -> example.com,
        and www.example.co.uk -> example.co.uk."""
        labels = self.normalize_domain(domain).split(".")
        if len(labels) <= 2:
            return ".".join(labels)
        tail2 = ".".join(labels[-2:])
        tail3 = ".".join(labels[-3:])
        if tail2 in self.MULTI_PART_SUFFIXES:
            return tail3
        return tail2

    def _scope_matches_any(self, norm_domain: str, normalized_scope: List[str]) -> bool:
        """Determine whether a requested domain is within an allowed scope.

        A domain is in scope if it exactly equals an allowed scope entry, is a
        subdomain of one (api.example.com vs example.com), or shares the same
        registrable domain as an allowed entry (luminadatamatics.com vs
        www.luminadatamatics.com). Ancestor matching is restricted to the
        registrable domain so requesting 'com' can never satisfy a host scope.
        """
        for allowed in normalized_scope:
            if not allowed:
                continue
            # A CIDR is a range of hosts, and the runner enforces it that way
            # (_match in app/roe/scope_check.py). Comparing it as a string refuses
            # a scope the runner will honor, and it is this method that recon's own
            # reconciliation gate runs with, so the divergence is not hypothetical.
            if "/" in allowed and "://" not in allowed:
                try:
                    if ipaddress.ip_address(norm_domain) in ipaddress.ip_network(allowed):
                        return True
                except ValueError:
                    continue
            if norm_domain == allowed:
                return True
            if norm_domain.endswith(f".{allowed}"):
                return True
            if self.registrable_domain(norm_domain) == self.registrable_domain(allowed):
                return True
        return False

    async def _ensure_roe_rules(self, investigation_id: str, scope_domains: list):
        try:
            roe_rules = await fetch_roe_rules(
                settings.RUNNER_URL,
                investigation_id,
                token=settings.RUNNER_ADMIN_TOKEN,
            )
            existing = set(r.get("pattern") for r in roe_rules if r.get("pattern"))
            for d in scope_domains:
                if d and d not in existing:
                    try:
                        await self._create_roe_rule(investigation_id, d, "allow", False)
                    except Exception as e:
                        print(f"Failed to create ROE rule for {d}: {e}")
        except Exception as e:
            print(f"Failed to ensure ROE rules: {e}")

    async def _create_roe_rule(self, investigation_id: str, pattern: str, rule_type: str, allow_aggressive: bool):
        import httpx
        url = f"{settings.RUNNER_URL.rstrip('/')}/roe/scope"
        headers = {"Authorization": f"Bearer {settings.RUNNER_ADMIN_TOKEN}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(url, headers=headers, json={
                "investigation_id": investigation_id,
                "pattern": pattern,
                "rule_type": rule_type,
                "allow_aggressive": allow_aggressive
            })

    async def start_session(self, request: ReconRequest) -> dict:
        # Validate scope before accepting
        try:
            scope_domains = await graph_client.get_program_scope(request.investigation_id)
            normalized_scope = [self.normalize_domain(d) for d in scope_domains]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not fetch program scope: {e}")

        # Ensure ROE rules exist for scope domains (auto-sync)
        try:
            await self._ensure_roe_rules(request.investigation_id, scope_domains)
        except Exception:
            pass

        # Reconcile the selection record (graph scope_domains) against the
        # enforcement record (the runner's ROE rules) before anything is
        # selected. Without this the two copies drift: recon picks hosts the
        # runner will refuse, and the failure surfaces as a rejected session
        # rather than as the scope bug it actually is.
        try:
            roe_rules = await fetch_roe_rules(
                settings.RUNNER_URL,
                request.investigation_id,
                token=settings.RUNNER_ADMIN_TOKEN,
            )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Could not fetch enforced scope from the active runner for "
                    f"{request.investigation_id}: {e}. Recon will not start a scan "
                    f"whose scope it cannot verify."
                ),
            )
        roe_scope = [r.get("pattern") for r in roe_rules if r.get("pattern")]
        # A host is aggressive-exempt only when an explicit allow rule for it
        # also says so. Deriving the set here, from the same fetch the scope
        # reconciliation just trusted, keeps the two in step.
        aggressive_patterns = [
            r.get("pattern") for r in roe_rules
            if r.get("rule_type") == "allow"
            and r.get("pattern")
            and r.get("allow_aggressive") is True
        ]

        reconciliation = reconcile(
            normalized_scope,
            roe_scope,
            matcher=self._scope_matches_any,
        )
        if not reconciliation.agreed:
            raise HTTPException(
                status_code=400,
                detail=ScopeReconciliationError(
                    reconciliation.unauthorized,
                    normalized_scope,
                    roe_scope,
                ).args[0],
                headers=out_of_scope_headers(reconciliation.unauthorized),
            )

        out_of_scope = []
        normalized_requested = []
        seen = set()
        for domain in request.domains:
            norm_domain = self.normalize_domain(domain)
            if norm_domain in seen:
                continue
            seen.add(norm_domain)
            normalized_requested.append(norm_domain)

            is_in_scope = self._scope_matches_any(norm_domain, normalized_scope)
            if not is_in_scope:
                out_of_scope.append(domain)

        if out_of_scope:
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = ReconSessionStatus(
                session_id=session_id,
                investigation_id=request.investigation_id,
                status="rejected",
                tool_statuses={},
                progress=0.0,
                current_tool=None,
                logs=[]
            )
            raise HTTPException(
                status_code=400,
                detail=f"Requested domains out of scope for program {request.investigation_id}: {', '.join(out_of_scope)}",
                headers=out_of_scope_headers(out_of_scope),
            )

        # Check for existing running session for same investigation and exact domains
        try:
            existing_sessions = await graph_client.list_recon_sessions(request.investigation_id)
            for s in existing_sessions:
                if s["status"] in ["running", "accepted"] and set(s["domains"]) == set(normalized_requested):
                    print(f"Deduplicating recon session for investigation {request.investigation_id}")
                    return {"session_id": s["id"], "duplicate_of": s["id"]}
        except Exception as e:
            print(f"Failed to check for existing sessions: {e}")

        session_id = str(uuid.uuid4())
        tool_statuses = {}
        for domain in normalized_requested:
            for tool in self.tools:
                tool_statuses[f"{tool.name}:{domain}"] = ToolStatus.WAITING

        self.sessions[session_id] = ReconSessionStatus(
            session_id=session_id,
            investigation_id=request.investigation_id,
            status="accepted",
            tool_statuses=tool_statuses,
            progress=0.0,
            current_tool=None,
            logs=[f"[{datetime.utcnow().strftime('%H:%M:%S')}] Recon session accepted."]
        )

        try:
            await graph_client.create_recon_session(session_id, request.investigation_id, normalized_requested, "accepted")
        except Exception as e:
            print(f"Warning: Failed to persist recon session {session_id} to graph_db: {e}")

        # Make the ROE aggressive allowance (if any) visible to run_session and
        # the conditional triggers, which key off _aggressive_allowed.
        self._aggressive_rules[session_id] = aggressive_patterns

        # Start background task with normalized domains
        asyncio.create_task(self.run_session(session_id, request.investigation_id, normalized_requested))

        return {"session_id": session_id}

orchestrator = ReconOrchestrator()


# The scope rejection's `detail` is a human sentence (it names the program id),
# which is too coarse for the panel to display safely. This header carries the
# rejected domains on their own so the UI can name them without re-parsing
# prose, while `detail` stays byte-identical for logs and existing consumers.
OUT_OF_SCOPE_HEADER = "X-Wraith-Out-Of-Scope"
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_MAX_OUT_OF_SCOPE_HEADER_HOSTS = 10


def out_of_scope_headers(domains: List[str]) -> Dict[str, str]:
    """Build the machine-readable rejection header.

    `domains` is raw client input, so only entries that are already bare
    hostnames are forwarded; anything else (CRLF, spaces, ports, markup) is
    dropped rather than escaped, since a partial list is still useful and an
    injected header never is.
    """
    safe = [d.strip() for d in domains if _SAFE_HOST_RE.match(d.strip())]
    if not safe:
        return {}
    return {OUT_OF_SCOPE_HEADER: ",".join(safe[:_MAX_OUT_OF_SCOPE_HEADER_HOSTS])}
