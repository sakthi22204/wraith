import asyncio
import uuid
from typing import Dict, List
from fastapi import HTTPException
from .schemas import ReconRequest, ReconSessionStatus, ToolStatus, ToolResults, HostResult
from .tools.subfinder import SubfinderTool
from .tools.httpx_probe import HttpxProbeTool
from .tools.katana import KatanaTool
from .tools.naabu import NaabuTool
from .graph_client import graph_client

def normalize_domain(value: str) -> str:
    """Strips scheme and path, lowercases result."""
    # Strip scheme
    if "://" in value:
        value = value.split("://", 1)[1]
    # Strip path/trailing slash
    if "/" in value:
        value = value.split("/", 1)[0]
    # Lowercase
    return value.lower()

class ReconOrchestrator:
    def __init__(self):
        self.sessions: Dict[str, ReconSessionStatus] = {}
        self.results: Dict[str, ToolResults] = {}
        self.tools = [
            SubfinderTool(),
            HttpxProbeTool(),
            KatanaTool(),
            NaabuTool()
        ]
        self.semaphore = asyncio.Semaphore(10)  # Concurrency limit
        self.running_tasks: Dict[str, List[asyncio.Task]] = {}

    async def run_session(self, session_id: str, program_id: str, domains: List[str]):
        session = self.sessions[session_id]
        session.status = "running"

        graph_session_id = None
        # Register session in graph_db
        try:
            graph_session = await graph_client.create_scan_session(program_id)
            graph_session_id = graph_session["id"]
        except Exception as e:
            print(f"Failed to register session in graph_db: {e}")

        tasks = []
        for domain in domains:
            for tool in self.tools:
                t = asyncio.create_task(self._run_tool(session_id, program_id, domain, tool))
                tasks.append(t)

        self.running_tasks[session_id] = tasks

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
             pass
        session.status = "completed"
        session.progress = 100.0

        if graph_session_id:
            try:
                await graph_client.update_scan_session(graph_session_id, "completed")
            except Exception as e:
                print(f"Failed to update session status in graph_db: {e}")

    async def _run_tool(self, session_id: str, program_id: str, domain: str, tool):
        async with self.semaphore:
            session = self.sessions[session_id]
            tool_key = f"{tool.name}:{domain}"
            session.tool_statuses[tool_key] = ToolStatus.RUNNING

            try:
                results = await tool.run(domain)
                await self._push_to_graph(program_id, results)

                # Store results for the session
                if session_id not in self.results:
                    self.results[session_id] = ToolResults()
                self.results[session_id].hosts.extend(results.hosts)
                self.results[session_id].ports.extend(results.ports)
                self.results[session_id].endpoints.extend(results.endpoints)

                session.tool_statuses[tool_key] = ToolStatus.COMPLETED
            except asyncio.TimeoutError:
                session.tool_statuses[tool_key] = ToolStatus.TIMED_OUT
            except Exception as e:
                print(f"Tool {tool.name} failed for {domain}: {e}")
                session.tool_statuses[tool_key] = ToolStatus.FAILED
            finally:
                # Update overall progress
                completed = sum(1 for s in session.tool_statuses.values()
                               if s in [ToolStatus.COMPLETED, ToolStatus.TIMED_OUT, ToolStatus.FAILED])
                session.progress = (completed / len(session.tool_statuses)) * 100.0

    async def _push_to_graph(self, program_id: str, results: ToolResults):
        # Maps for caching IDs to avoid redundant lookups if needed,
        # but graph_db is idempotent so we just push.

        for host in results.hosts:
            await graph_client.upsert_host(program_id, host)

        for port in results.ports:
            # First upsert the host to get its ID (though we know value is unique)
            # The graph_db POST /programs/{id}/hosts returns the host object including id
            host_obj = await graph_client.upsert_host(program_id, HostResult(value=port.host, source_tool=port.source_tool))
            await graph_client.upsert_port(host_obj["id"], port)

        for endpoint in results.endpoints:
            host_obj = await graph_client.upsert_host(program_id, HostResult(value=endpoint.host, source_tool=endpoint.source_tool))
            await graph_client.upsert_endpoint(host_obj["id"], endpoint)

    async def cancel_session(self, session_id: str):
        if session_id in self.running_tasks:
            for task in self.running_tasks[session_id]:
                task.cancel()
            del self.running_tasks[session_id]

        if session_id in self.sessions:
            self.sessions[session_id].status = "cancelled"

    async def start_session(self, request: ReconRequest) -> str:
        # Validate scope before accepting
        try:
            scope_domains = await graph_client.get_program_scope(request.program_id)
        except Exception as e:
            # If program doesn't exist or graph_db is down, we can't validate scope.
            # Reject to be safe.
            raise HTTPException(status_code=400, detail=f"Could not fetch program scope: {e}")

        out_of_scope = []
        normalized_allowed = [normalize_domain(d) for d in scope_domains]

        for domain in request.domains:
            norm_domain = normalize_domain(domain)
            is_in_scope = False
            for allowed in normalized_allowed:
                if norm_domain == allowed or norm_domain.endswith(f".{allowed}"):
                    is_in_scope = True
                    break
            if not is_in_scope:
                out_of_scope.append(domain)

        if out_of_scope:
            session_id = str(uuid.uuid4())
            self.sessions[session_id] = ReconSessionStatus(
                session_id=session_id,
                program_id=request.program_id,
                status="rejected",
                tool_statuses={},
                progress=0.0
            )
            raise HTTPException(
                status_code=400,
                detail=f"Requested domains out of scope for program {request.program_id}: {', '.join(out_of_scope)}"
            )

        session_id = str(uuid.uuid4())
        tool_statuses = {}
        for domain in request.domains:
            for tool in self.tools:
                tool_statuses[f"{tool.name}:{domain}"] = ToolStatus.PENDING

        self.sessions[session_id] = ReconSessionStatus(
            session_id=session_id,
            program_id=request.program_id,
            status="accepted",
            tool_statuses=tool_statuses,
            progress=0.0
        )

        # Start background task
        asyncio.create_task(self.run_session(session_id, request.program_id, request.domains))

        return session_id

orchestrator = ReconOrchestrator()
