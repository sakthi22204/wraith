from fastapi import APIRouter, Depends, HTTPException, Query
import os
import json
from typing import List, Optional
from pydantic import BaseModel
from ..schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVECreate, GraphResponse, FalsePositivePattern,
    ReconSession, AgentSession, Investigation, InvestigationCreate
)
from ..client import neo4j_client
from ..repository import Neo4jRepository
from ..auth import require_admin_token
import httpx
from ..config import settings as graph_settings

router = APIRouter()

async def get_repo():
    session = await neo4j_client.get_session()
    try:
        yield Neo4jRepository(session)
    finally:
        await session.close()

class ReviewRequest(BaseModel):
    decision: str # "confirmed" | "false_positive"
    note: str

class CorroborateRequest(BaseModel):
    source_name: str

class FPCheckRequest(BaseModel):
    vuln_type: str
    endpoint: str
    parameter: Optional[str] = None

# Investigation Endpoints (New Primary workflow)
@router.post("/investigations", response_model=Investigation)
async def create_investigation(request: InvestigationCreate, repo: Neo4jRepository = Depends(get_repo)):
    investigation = await repo.create_investigation(request)

    # Automatically trigger automatic recon session via recon_orchestrator
    recon_url = os.getenv("RECON_ORCHESTRATOR_URL", "http://recon_orchestrator:8002/api/v1/recon")
    headers = {"Authorization": f"Bearer {graph_settings.ADMIN_API_TOKEN}"}
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            payload = {
                "investigation_id": investigation.id,
                "domains": [investigation.target]
            }
            resp = await client.post(f"{recon_url}/start", json=payload, headers=headers)
            if resp.status_code not in [200, 202]:
                print(f"Warning: automatic recon response status {resp.status_code}: {resp.text}")
    except Exception as e:
        print(f"Warning: Failed to trigger automatic recon: {e}")

    return investigation

@router.get("/investigations", response_model=List[Investigation])
async def list_investigations(repo: Neo4jRepository = Depends(get_repo)):
    return await repo.list_investigations()

@router.get("/investigations/{investigation_id}", response_model=Investigation)
async def get_investigation(investigation_id: str, repo: Neo4jRepository = Depends(get_repo)):
    investigation = await repo.get_investigation(investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation

@router.delete("/investigations/{investigation_id}", dependencies=[Depends(require_admin_token)])
async def delete_investigation(investigation_id: str, confirm: bool = Query(False), repo: Neo4jRepository = Depends(get_repo)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required to delete investigation and its subgraph.")

    await repo.delete_investigation_recursive(investigation_id)

    # Cross-service cascade delete
    runner_url = os.getenv("ACTIVE_EXPLOIT_RUNNER_URL", "http://active_exploit_runner:8004/api/v1")
    headers = {"Authorization": f"Bearer {graph_settings.ADMIN_API_TOKEN}"}

    warning = None
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.delete(f"{runner_url}/investigations/{investigation_id}/purge", headers=headers)
            if resp.status_code != 200:
                warning = f"Failed to purge investigation data from active_exploit_runner: {resp.text}"
    except Exception as e:
        warning = f"Error calling active_exploit_runner purge: {e}"

    res = {"status": "deleted"}
    if warning:
        res["warning"] = warning

    return res

@router.get("/investigations/{investigation_id}/graph", response_model=GraphResponse)
async def get_investigation_graph(investigation_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_attack_surface(investigation_id)

@router.get("/investigations/{investigation_id}/findings", response_model=List[Finding])
async def get_investigation_findings(investigation_id: str, min_severity: str = "info", repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_by_severity(investigation_id, min_severity)

@router.post("/investigations/{investigation_id}/dedupe")
async def deduplicate_investigation_findings(investigation_id: str, repo: Neo4jRepository = Depends(get_repo)):
    count = await repo.deduplicate_findings(investigation_id)
    return {"merged_count": count}

@router.get("/investigations/{investigation_id}/findings/review-queue", response_model=List[Finding])
async def get_investigation_review_queue(investigation_id: str, threshold: float = 0.7, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_needing_review(investigation_id, threshold)

@router.post("/investigations/{investigation_id}/findings/check-false-positive", response_model=List[FalsePositivePattern])
async def check_investigation_false_positive(investigation_id: str, request: FPCheckRequest, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.check_known_false_positive_patterns(investigation_id, request.vuln_type, request.endpoint, request.parameter)

# Legacy Program endpoints point directly to Investigations
@router.post("/programs", response_model=Program)
async def create_program(program: ProgramCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.create_program(program)

@router.get("/programs", response_model=List[Program])
async def list_programs(repo: Neo4jRepository = Depends(get_repo)):
    return await repo.list_programs()

@router.get("/programs/{program_id}", response_model=Program)
async def get_program(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    program = await repo.get_program(program_id)
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return program

@router.delete("/programs/{program_id}", dependencies=[Depends(require_admin_token)])
async def delete_program(program_id: str, confirm: bool = Query(False), repo: Neo4jRepository = Depends(get_repo)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required to delete program and its subgraph.")

    await repo.delete_program_recursive(program_id)

    # Cross-service cascade delete
    runner_url = os.getenv("ACTIVE_EXPLOIT_RUNNER_URL", "http://active_exploit_runner:8004/api/v1")
    headers = {"Authorization": f"Bearer {graph_settings.ADMIN_API_TOKEN}"}

    warning = None
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.delete(f"{runner_url}/programs/{program_id}/purge", headers=headers)
            if resp.status_code != 200:
                warning = f"Failed to purge program data from active_exploit_runner: {resp.text}"
    except Exception as e:
        warning = f"Error calling active_exploit_runner purge: {e}"

    res = {"status": "deleted"}
    if warning:
        res["warning"] = warning

    return res

@router.get("/programs/{program_id}/graph", response_model=GraphResponse)
async def get_program_graph(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_attack_surface(program_id)

@router.get("/programs/{program_id}/findings", response_model=List[Finding])
async def get_findings(program_id: str, min_severity: str = "info", repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_by_severity(program_id, min_severity)

@router.post("/programs/{program_id}/dedupe")
async def deduplicate_findings(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    count = await repo.deduplicate_findings(program_id)
    return {"merged_count": count}

@router.get("/programs/{program_id}/findings/review-queue", response_model=List[Finding])
async def get_review_queue(program_id: str, threshold: float = 0.7, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_needing_review(program_id, threshold)

@router.post("/programs/{program_id}/findings/check-false-positive", response_model=List[FalsePositivePattern])
async def check_false_positive(program_id: str, request: FPCheckRequest, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.check_known_false_positive_patterns(program_id, request.vuln_type, request.endpoint, request.parameter)

# Sessions and Nodes endpoints with multi-id fallback support
@router.post("/scan-sessions")
async def create_scan_session(investigation_id: Optional[str] = None, program_id: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    inv_id = investigation_id or program_id
    if not inv_id:
        raise HTTPException(status_code=400, detail="investigation_id or program_id is required")
    return await repo.create_scan_session(inv_id)

@router.patch("/scan-sessions/{session_id}")
async def update_scan_session(session_id: str, status: str, repo: Neo4jRepository = Depends(get_repo)):
    await repo.update_scan_session(session_id, status)
    return {"status": "updated"}

# Recon Session Management
@router.post("/recon-sessions", response_model=ReconSession)
async def create_recon_session(session_id: str, domains: List[str], status: str, investigation_id: Optional[str] = None, program_id: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    inv_id = investigation_id or program_id
    if not inv_id:
        raise HTTPException(status_code=400, detail="investigation_id or program_id is required")
    return await repo.create_recon_session(session_id, inv_id, domains, status)

@router.patch("/recon-sessions/{session_id}", response_model=ReconSession)
async def update_recon_session(session_id: str, status: str, tool_results: Optional[dict] = None, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.update_recon_session_status(session_id, status, tool_results)

@router.get("/recon-sessions", response_model=List[ReconSession])
async def list_recon_sessions(investigation_id: Optional[str] = None, program_id: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    inv_id = investigation_id or program_id
    if not inv_id:
        raise HTTPException(status_code=400, detail="investigation_id or program_id is required")
    return await repo.list_recon_sessions(inv_id)

@router.get("/recon-sessions/{session_id}", response_model=ReconSession)
async def get_recon_session(session_id: str, repo: Neo4jRepository = Depends(get_repo)):
    session = await repo.get_recon_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Recon session not found")
    return session

# Agent Session Management
def _parse_list_param(value: Optional[str]) -> Optional[List[str]]:
    """Parse a JSON-encoded list query param (sent by the exploit agent client).

    FastAPI 0.141+ no longer collects repeated scalar query params into List[str]
    (e.g. ?reasoning_log=a&reasoning_log=b arrives as None). The client therefore
    sends the list JSON-encoded in a single param. Fall back to comma-separated or
    single-value for robustness.
    """
    if value is None:
        return None
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except (ValueError, TypeError):
        pass
    if "," in value:
        return [item.strip() for item in value.split(",") if item.strip()]
    return [value]

@router.post("/agent-sessions", response_model=AgentSession)
async def create_agent_session(session_id: str, status: str, investigation_id: Optional[str] = None, program_id: Optional[str] = None, iteration_count: int = 0, tools_used: Optional[str] = None, reasoning_log: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    inv_id = investigation_id or program_id
    if not inv_id:
        raise HTTPException(status_code=400, detail="investigation_id or program_id is required")
    return await repo.create_agent_session(session_id, inv_id, status, iteration_count, _parse_list_param(tools_used) or [], _parse_list_param(reasoning_log) or [])

@router.patch("/agent-sessions/{session_id}", response_model=AgentSession)
async def update_agent_session(session_id: str, status: str, iteration_count: Optional[int] = None, tools_used: Optional[str] = None, final_report: Optional[str] = None, reasoning_log: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.update_agent_session_status(session_id, status, iteration_count, _parse_list_param(tools_used), final_report, _parse_list_param(reasoning_log))

@router.get("/agent-sessions", response_model=List[AgentSession])
async def list_agent_sessions(investigation_id: Optional[str] = None, program_id: Optional[str] = None, repo: Neo4jRepository = Depends(get_repo)):
    inv_id = investigation_id or program_id
    if inv_id:
        return await repo.list_agent_sessions(inv_id)
    else:
        return await repo.list_all_agent_sessions()

@router.get("/agent-sessions/{session_id}", response_model=AgentSession)
async def get_agent_session(session_id: str, repo: Neo4jRepository = Depends(get_repo)):
    session = await repo.get_agent_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Agent session not found")
    return session

@router.post("/agent-sessions/cleanup-orphaned")
async def cleanup_orphaned_agent_sessions(repo: Neo4jRepository = Depends(get_repo)):
    count = await repo.cleanup_orphaned_agent_sessions()
    return {"cleaned_count": count}

@router.post("/findings/{finding_id}/session/{session_id}")
async def link_finding_to_session(finding_id: str, session_id: str, repo: Neo4jRepository = Depends(get_repo)):
    await repo.link_finding_to_session(finding_id, session_id)
    return {"status": "linked"}

@router.post("/tools")
async def upsert_tool(name: str, version: str, repo: Neo4jRepository = Depends(get_repo)):
    t_id = await repo.upsert_tool(name, version)
    return {"id": t_id}

@router.post("/findings/{finding_id}/tool/{tool_id}")
async def link_finding_to_tool(finding_id: str, tool_id: str, repo: Neo4jRepository = Depends(get_repo)):
    await repo.link_finding_to_tool(finding_id, tool_id)
    return {"status": "linked"}

@router.post("/investigations/{investigation_id}/hosts", response_model=Host)
async def upsert_host(investigation_id: str, host: HostCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_host(host, investigation_id)

@router.post("/programs/{program_id}/hosts", response_model=Host)
async def upsert_host_alias(program_id: str, host: HostCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_host(host, program_id)

@router.post("/hosts/{host_id}/ports", response_model=Port)
async def upsert_port(host_id: str, port: PortCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_port(port, host_id)

@router.post("/ports/{port_id}/service", response_model=Service)
async def upsert_service(port_id: str, service: ServiceCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_service(service, port_id)

@router.post("/hosts/{host_id}/endpoints", response_model=Endpoint)
async def upsert_endpoint(host_id: str, endpoint: EndpointCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_endpoint(endpoint, host_id)

@router.post("/endpoints/{endpoint_id}/parameters", response_model=Parameter)
async def upsert_parameter(endpoint_id: str, param: ParameterCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.upsert_parameter(param, endpoint_id)

@router.post("/findings", response_model=Finding)
async def create_finding(finding: FindingCreate, repo: Neo4jRepository = Depends(get_repo)):
    if finding.target_type.lower() not in ["endpoint", "parameter"]:
        raise HTTPException(status_code=400, detail="target_type must be endpoint or parameter")
    try:
        return await repo.create_finding(finding)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/hosts/{host_id}/attack-paths")
async def get_attack_paths(host_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.find_attack_paths(host_id)

@router.post("/findings/{finding_id}/cve")
async def link_cve(finding_id: str, cve: CVECreate, repo: Neo4jRepository = Depends(get_repo)):
    await repo.link_finding_to_cve(finding_id, cve)
    return {"status": "success"}

@router.post("/findings/{finding_id}/review", response_model=Finding)
async def review_finding(finding_id: str, request: ReviewRequest, repo: Neo4jRepository = Depends(get_repo)):
    if request.decision not in ["confirmed", "false_positive"]:
         raise HTTPException(status_code=400, detail="decision must be confirmed or false_positive")
    return await repo.mark_reviewed(finding_id, request.decision, request.note)

@router.post("/findings/{finding_id}/corroborate", response_model=Finding)
async def corroborate_finding(finding_id: str, request: CorroborateRequest, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.add_corroboration(finding_id, request.source_name)
