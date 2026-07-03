from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from ..schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVECreate, GraphResponse
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
