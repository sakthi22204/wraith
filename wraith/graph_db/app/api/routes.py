from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from pydantic import BaseModel
from ..schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVECreate, GraphResponse, FalsePositivePattern
)
from ..client import neo4j_client
from ..repository import Neo4jRepository

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

@router.post("/programs", response_model=Program)
async def create_program(program: ProgramCreate, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.create_program(program)

@router.post("/scan-sessions")
async def create_scan_session(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.create_scan_session(program_id)

@router.patch("/scan-sessions/{session_id}")
async def update_scan_session(session_id: str, status: str, repo: Neo4jRepository = Depends(get_repo)):
    await repo.update_scan_session(session_id, status)
    return {"status": "updated"}

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

@router.post("/programs/{program_id}/hosts", response_model=Host)
async def upsert_host(program_id: str, host: HostCreate, repo: Neo4jRepository = Depends(get_repo)):
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
    if finding.target_type not in ["endpoint", "parameter"]:
        raise HTTPException(status_code=400, detail="target_type must be endpoint or parameter")
    return await repo.create_finding(finding)

@router.get("/programs/{program_id}/graph", response_model=GraphResponse)
async def get_program_graph(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_attack_surface(program_id)

@router.get("/programs/{program_id}/findings", response_model=List[Finding])
async def get_findings(program_id: str, min_severity: str = "info", repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_by_severity(program_id, min_severity)

@router.get("/hosts/{host_id}/attack-paths")
async def get_attack_paths(host_id: str, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.find_attack_paths(host_id)

@router.post("/programs/{program_id}/dedupe")
async def deduplicate_findings(program_id: str, repo: Neo4jRepository = Depends(get_repo)):
    count = await repo.deduplicate_findings(program_id)
    return {"merged_count": count}

@router.post("/findings/{finding_id}/cve")
async def link_cve(finding_id: str, cve: CVECreate, repo: Neo4jRepository = Depends(get_repo)):
    await repo.link_finding_to_cve(finding_id, cve)
    return {"status": "success"}

@router.delete("/programs/{program_id}")
async def delete_program(program_id: str, confirm: bool = Query(False), repo: Neo4jRepository = Depends(get_repo)):
    if not confirm:
        raise HTTPException(status_code=400, detail="Confirmation required to delete program and its subgraph.")

    await repo.delete_program_recursive(program_id)
    return {"status": "deleted"}

# New Phase 8 Review Queue Endpoints

@router.get("/programs/{program_id}/findings/review-queue", response_model=List[Finding])
async def get_review_queue(program_id: str, threshold: float = 0.7, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.get_findings_needing_review(program_id, threshold)

@router.post("/findings/{finding_id}/review", response_model=Finding)
async def review_finding(finding_id: str, request: ReviewRequest, repo: Neo4jRepository = Depends(get_repo)):
    if request.decision not in ["confirmed", "false_positive"]:
         raise HTTPException(status_code=400, detail="decision must be confirmed or false_positive")
    return await repo.mark_reviewed(finding_id, request.decision, request.note)

@router.post("/findings/{finding_id}/corroborate", response_model=Finding)
async def corroborate_finding(finding_id: str, request: CorroborateRequest, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.add_corroboration(finding_id, request.source_name)

@router.post("/programs/{program_id}/findings/check-false-positive", response_model=List[FalsePositivePattern])
async def check_false_positive(program_id: str, request: FPCheckRequest, repo: Neo4jRepository = Depends(get_repo)):
    return await repo.check_known_false_positive_patterns(program_id, request.vuln_type, request.endpoint, request.parameter)
