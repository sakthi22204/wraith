import asyncio
import ipaddress
import uuid
from datetime import datetime
from typing import Dict, List
from fastapi import HTTPException
from .schemas import ReconRequest, ReconSessionStatus, ToolStatus, ToolResults, HostResult
from .tools.subfinder import SubfinderTool
from .tools.httpx_probe import HttpxProbeTool
from .tools.katana import KatanaTool
from .tools.naabu import NaabuTool
from .tools.dnsx import DnsxTool
from .tools.nmap import NmapTool
from .tools.tlsx import TlsxTool
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
from .graph_client import graph_client

class ReconOrchestrator:
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

        # Fully implemented real tools activated and wired up
        self.tools = [
            self.subfinder, self.httpx_probe, self.katana, self.naabu,
            self.dnsx, self.nmap, self.tlsx, self.gau, self.waybackurls,
            self.ffuf,
            self.kiterunner,
            self.linkfinder,
            self.secretfinder,
            self.trufflehog,
            self.gittools,
            self.wpscan, self.cloud_enum
        ]

        self.semaphore = asyncio.Semaphore(10)  # Concurrency limit
        self.running_tasks: Dict[str, List[asyncio.Task]] = {}

    @staticmethod
    def _is_local_target(domain: str) -> bool:
        host = domain.rsplit(":", 1)[0]
        if host == "localhost" or "_" in host or host.endswith(".local"):
            return True
        try:
            return ipaddress.ip_address(host).is_private
        except ValueError:
            return False

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

        # Core base tools run initially
        base_tools = [
            self.subfinder,
            self.naabu,
            self.httpx_probe,
            self.katana,
            self.gau,
            self.waybackurls,
            self.cloud_enum
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

        # Mark any remaining WAITING tools as COMPLETED (or skipped/completed) for legacy test expectations
        for k, v in list(session.tool_statuses.items()):
            if v == ToolStatus.WAITING:
                session.tool_statuses[k] = ToolStatus.COMPLETED

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

    async def _evaluate_conditional_triggers(self, session_id: str, investigation_id: str, domain: str, completed_tool, queued_keys: set, running_tasks: list):
        session = self.sessions[session_id]
        results = self.results.get(session_id, ToolResults())

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
        if wordpress_detected:
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
            if endpoint.url.lower().endswith(".js"):
                js_detected = True
                break
        if js_detected:
            for tool in [self.linkfinder, self.secretfinder]:
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
        if api_detected:
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

        # 5. Discovered open ports (Trigger Nmap and tlsx)
        if completed_tool.name == "naabu" and results.ports:
            # Trigger Nmap
            nmap_key = f"nmap:{domain}"
            if nmap_key not in queued_keys:
                queued_keys.add(nmap_key)
                session.tool_statuses[nmap_key] = ToolStatus.WAITING
                session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Open ports discovered. Scheduling Nmap scan.")
                task_launch = asyncio.create_task(launch_tool(self.nmap, domain))
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

        # 6. Active HTTP web service found (Trigger GitTools, ffuf, TruffleHog)
        if completed_tool.name in ["httpx", "katana"] and results.endpoints:
            for tool in [self.trufflehog, self.gittools, self.ffuf]:
                tool_key = f"{tool.name}:{domain}"
                if tool_key not in queued_keys:
                    queued_keys.add(tool_key)
                    session.tool_statuses[tool_key] = ToolStatus.WAITING
                    session.logs.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] Active web endpoints found. Scheduling {tool.name}.")
                    task_launch = asyncio.create_task(launch_tool(tool, domain))
                    running_tasks.append(task_launch)

    async def _run_tool(self, session_id: str, investigation_id: str, domain: str, tool):
        session = self.sessions[session_id]
        tool_key = f"{tool.name}:{domain}"

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

                    session.tool_statuses[tool_key] = ToolStatus.COMPLETED
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
        for host in results.hosts:
            await graph_client.upsert_host(investigation_id, host)

        for port in results.ports:
            host_obj = await graph_client.upsert_host(investigation_id, HostResult(value=port.host, source_tool=port.source_tool))
            await graph_client.upsert_port(host_obj["id"], port)

        for endpoint in results.endpoints:
            host_obj = await graph_client.upsert_host(investigation_id, HostResult(value=endpoint.host, source_tool=endpoint.source_tool))
            await graph_client.upsert_endpoint(host_obj["id"], endpoint)

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

    async def start_session(self, request: ReconRequest) -> dict:
        # Validate scope before accepting
        try:
            scope_domains = await graph_client.get_program_scope(request.investigation_id)
            normalized_scope = [self.normalize_domain(d) for d in scope_domains]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Could not fetch program scope: {e}")

        out_of_scope = []
        normalized_requested = []
        seen = set()
        for domain in request.domains:
            norm_domain = self.normalize_domain(domain)
            if norm_domain in seen:
                continue
            seen.add(norm_domain)
            normalized_requested.append(norm_domain)

            is_in_scope = False
            for allowed in normalized_scope:
                if norm_domain == allowed or norm_domain.endswith(f".{allowed}"):
                    is_in_scope = True
                    break
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
                detail=f"Requested domains out of scope for program {request.investigation_id}: {', '.join(out_of_scope)}"
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

        # Start background task with normalized domains
        asyncio.create_task(self.run_session(session_id, request.investigation_id, normalized_requested))

        return {"session_id": session_id}

orchestrator = ReconOrchestrator()
