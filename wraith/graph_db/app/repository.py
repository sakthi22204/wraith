import hashlib
import json
import uuid
import re
import asyncio
import random
from datetime import datetime
from typing import List, Optional, Dict, Any
from neo4j import AsyncSession
import neo4j.exceptions
from .schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVE, CVECreate, Node, Link, GraphResponse,
    FindingStatus, FalsePositivePattern, FalsePositivePatternCreate,
    ReconSession, AgentSession, Investigation, InvestigationCreate
)

def generate_id(*args, investigation_id: str = None) -> str:
    """
    Generate deterministic ID from arguments.
    If investigation_id is provided, it's prepended to ensure cross-investigation isolation.
    """
    parts = []
    if investigation_id:
        parts.append(investigation_id)
    parts.extend(str(arg) for arg in args)
    seed = ":".join(parts)
    return hashlib.sha256(seed.encode()).hexdigest()

def retry_on_transient_error(max_retries=3, initial_delay=0.05):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            retries = 0
            delay = initial_delay
            while True:
                try:
                    return await func(*args, **kwargs)
                except neo4j.exceptions.TransientError as e:
                    if retries >= max_retries:
                        print(f"Max retries reached for {func.__name__} after TransientError: {e}")
                        raise
                    # Check for specific code if possible, but Transaction.Outdated is common for this
                    retries += 1
                    sleep_time = delay * (1 + random.random()) # jitter
                    print(f"TransientError in {func.__name__}, retry {retries}/{max_retries} in {sleep_time:.3f}s: {e}")
                    await asyncio.sleep(sleep_time)
                    delay *= 2 # exponential backoff
                except Exception:
                    raise
        return wrapper
    return decorator

class Neo4jRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def initialize_db(self):
        constraints = [
            "CREATE CONSTRAINT program_id IF NOT EXISTS FOR (p:Program) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
            "CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT parameter_id IF NOT EXISTS FOR (p:Parameter) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT finding_id IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT tool_id IF NOT EXISTS FOR (t:Tool) REQUIRE t.id IS UNIQUE",
            "CREATE CONSTRAINT scansession_id IF NOT EXISTS FOR (s:ScanSession) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT reconsession_id IF NOT EXISTS FOR (r:ReconSession) REQUIRE r.id IS UNIQUE",
            "CREATE CONSTRAINT fppattern_id IF NOT EXISTS FOR (f:FalsePositivePattern) REQUIRE f.id IS UNIQUE",
            "CREATE CONSTRAINT agentsession_id IF NOT EXISTS FOR (a:AgentSession) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT investigation_id IF NOT EXISTS FOR (i:Investigation) REQUIRE i.id IS UNIQUE"
        ]
        for query in constraints:
            await self.session.run(query)

    async def upsert_tool(self, name: str, version: str) -> str:
        t_id = generate_id(name, version)
        query = """
        MERGE (t:Tool {id: $id})
        SET t.name = $name, t.version = $version
        RETURN t.id as id
        """
        result = await self.session.run(query, id=t_id, name=name, version=version)
        record = await result.single()
        return record["id"]

    async def link_finding_to_tool(self, finding_id: str, tool_id: str) -> None:
        query = """
        MATCH (f:Finding {id: $finding_id}), (t:Tool {id: $tool_id})
        MERGE (f)-[:DISCOVERED_BY]->(t)
        """
        await self.session.run(query, finding_id=finding_id, tool_id=tool_id)

    async def create_scan_session(self, investigation_id: str) -> dict:
        s_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MERGE (s:ScanSession {id: $s_id})
        ON CREATE SET s.started_at = $started_at, s.status = "running"
        MERGE (s)-[:TARGETED]->(i)
        RETURN s
        """
        result = await self.session.run(query, investigation_id=investigation_id, s_id=s_id, started_at=now)
        record = await result.single()
        return dict(record["s"])

    async def update_scan_session(self, session_id: str, status: str) -> None:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (s:ScanSession {id: $session_id})
        SET s.status = $status
        """
        if status == "completed":
            query += ", s.ended_at = $now"
        await self.session.run(query, session_id=session_id, status=status, now=now)

    async def link_finding_to_session(self, finding_id: str, session_id: str) -> None:
        query = """
        MATCH (f:Finding {id: $finding_id}), (s:ScanSession {id: $session_id})
        MERGE (s)-[:PRODUCED]->(f)
        """
        await self.session.run(query, finding_id=finding_id, session_id=session_id)

    async def create_investigation(self, investigation: InvestigationCreate) -> Investigation:
        i_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        name = investigation.name.strip() if investigation.name else f"Investigation of {investigation.target}"
        query = """
        MERGE (i:Investigation {id: $id})
        ON CREATE SET i.name = $name, i.target = $target, i.scope_domains = $scope_domains, i.created_at = $created_at, i.platform = $platform
        RETURN i
        """
        result = await self.session.run(query, id=i_id, name=name, target=investigation.target,
                                      scope_domains=[investigation.target], created_at=now,
                                      platform=investigation.platform or "automatic")
        record = await result.single()
        return Investigation(**record["i"])

    @retry_on_transient_error()
    async def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        query = "MATCH (i:Investigation {id: $id}) RETURN i"
        result = await self.session.run(query, id=investigation_id)
        record = await result.single()
        if not record:
            return None
        return Investigation(**record["i"])

    @retry_on_transient_error()
    async def list_investigations(self) -> List[Investigation]:
        query = "MATCH (i:Investigation) RETURN i"
        result = await self.session.run(query)
        investigations = []
        async for record in result:
            investigations.append(Investigation(**record["i"]))
        return investigations

    # Legacy Program support
    async def create_program(self, program: ProgramCreate) -> Program:
        target = program.scope_domains[0] if program.scope_domains else "unknown"
        investigation_create = InvestigationCreate(name=program.name, target=target, platform=program.platform)
        inv = await self.create_investigation(investigation_create)
        # Use APOC or MERGE to keep them in-sync as a fallback
        return Program(id=inv.id, name=inv.name, platform=inv.platform, scope_domains=inv.scope_domains, created_at=inv.created_at)

    @retry_on_transient_error()
    async def get_program(self, program_id: str) -> Optional[Program]:
        inv = await self.get_investigation(program_id)
        if not inv:
            return None
        return Program(id=inv.id, name=inv.name, platform=inv.platform, scope_domains=inv.scope_domains, created_at=inv.created_at)

    @retry_on_transient_error()
    async def list_programs(self) -> List[Program]:
        invs = await self.list_investigations()
        return [Program(id=i.id, name=i.name, platform=i.platform, scope_domains=i.scope_domains, created_at=i.created_at) for i in invs]

    async def upsert_host(self, host: HostCreate, investigation_id: str) -> Host:
        h_id = generate_id(host.value, investigation_id=investigation_id)
        now = datetime.utcnow().isoformat()
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MERGE (h:Host {id: $h_id})
        ON CREATE SET h.value = $value, h.first_seen = $now, h.last_seen = $now
        ON MATCH SET h.last_seen = $now
        MERGE (i)-[:IN_SCOPE]->(h)
        RETURN h
        """
        result = await self.session.run(query, investigation_id=investigation_id, h_id=h_id, value=host.value, now=now)
        record = await result.single()
        return Host(**record["h"])

    async def upsert_port(self, port: PortCreate, host_id: str) -> Port:
        # We need protocol for uniqueness
        p_id = generate_id(host_id, port.number, port.protocol)
        query = """
        MATCH (h:Host {id: $host_id})
        MERGE (p:Port {id: $p_id})
        SET p.number = $number, p.protocol = $protocol, p.state = $state, p.source_tool = $source_tool
        MERGE (h)-[:HAS_PORT]->(p)
        RETURN p
        """
        result = await self.session.run(query, host_id=host_id, p_id=p_id, number=port.number,
                                      protocol=port.protocol, state=port.state, source_tool=port.source_tool)
        record = await result.single()
        return Port(**record["p"])

    async def upsert_service(self, service: ServiceCreate, port_id: str) -> Service:
        s_id = generate_id(port_id, service.name)
        query = """
        MATCH (p:Port {id: $port_id})
        MERGE (s:Service {id: $s_id})
        SET s.name = $name, s.version = $version, s.banner = $banner
        MERGE (p)-[:RUNS]->(s)
        RETURN s
        """
        result = await self.session.run(query, port_id=port_id, s_id=s_id, name=service.name,
                                      version=service.version, banner=service.banner)
        record = await result.single()
        return Service(**record["s"])

    async def upsert_endpoint(self, endpoint: EndpointCreate, host_id: str) -> Endpoint:
        e_id = generate_id(host_id, endpoint.url, endpoint.method)
        now = datetime.utcnow().isoformat()
        query = """
        MATCH (h:Host {id: $host_id})
        MERGE (e:Endpoint {id: $e_id})
        ON CREATE SET e.url = $url, e.method = $method, e.first_seen = $now, e.source_tool = $source_tool
        ON MATCH SET e.source_tool = $source_tool
        MERGE (h)-[:HAS_ENDPOINT]->(e)
        RETURN e
        """
        result = await self.session.run(query, host_id=host_id, e_id=e_id, url=endpoint.url,
                                      method=endpoint.method, now=now, source_tool=endpoint.source_tool)
        record = await result.single()
        return Endpoint(**record["e"])

    async def upsert_parameter(self, param: ParameterCreate, endpoint_id: str) -> Parameter:
        p_id = generate_id(endpoint_id, param.name, param.location)
        query = """
        MATCH (e:Endpoint {id: $endpoint_id})
        MERGE (p:Parameter {id: $p_id})
        SET p.name = $name, p.location = $location, p.param_type = $param_type
        MERGE (e)-[:HAS_PARAMETER]->(p)
        RETURN p
        """
        result = await self.session.run(query, endpoint_id=endpoint_id, p_id=p_id, name=param.name,
                                      location=param.location, param_type=param.param_type)
        record = await result.single()
        return Parameter(**record["p"])

    async def create_finding(self, finding: FindingCreate) -> Finding:
        f_id = generate_id(finding.vuln_type, finding.target_id)
        now_utc = finding.discovered_at.isoformat() + "Z"

        if finding.target_type.lower() == "endpoint":
            query = """
            MATCH (t:Endpoint {id: $target_id})
            MERGE (f:Finding {id: $f_id})
            SET f.vuln_type = $vuln_type, f.severity = $severity, f.confidence = $confidence,
                f.status = $status, f.description = $description, f.discovered_at = $discovered_at,
                f.ai_confidence = $ai_confidence, f.ai_reasoning = $ai_reasoning,
                f.corroborating_sources = $corroborating_sources,
                f.cvss_vector = $cvss_vector, f.evidence = $evidence
            MERGE (t)-[:HAS_FINDING]->(f)
            RETURN f
            """
        elif finding.target_type.lower() == "parameter":
            query = """
            MATCH (t:Parameter {id: $target_id})
            MERGE (f:Finding {id: $f_id})
            SET f.vuln_type = $vuln_type, f.severity = $severity, f.confidence = $confidence,
                f.status = $status, f.description = $description, f.discovered_at = $discovered_at,
                f.ai_confidence = $ai_confidence, f.ai_reasoning = $ai_reasoning,
                f.corroborating_sources = $corroborating_sources,
                f.cvss_vector = $cvss_vector, f.evidence = $evidence
            MERGE (t)-[:HAS_FINDING]->(f)
            RETURN f
            """
        else:
            raise ValueError(f"Invalid target_type: {finding.target_type}")

        result = await self.session.run(query, target_id=finding.target_id, f_id=f_id, vuln_type=finding.vuln_type,
                                      severity=finding.severity, confidence=finding.confidence,
                                      status=finding.status.value, description=finding.description,
                                      discovered_at=now_utc, ai_confidence=finding.ai_confidence,
                                      ai_reasoning=finding.ai_reasoning,
                                      corroborating_sources=finding.corroborating_sources,
                                      cvss_vector=finding.cvss_vector,
                                      evidence=finding.evidence)
        record = await result.single()
        return Finding(**record["f"])

    async def add_corroboration(self, finding_id: str, source_name: str) -> Finding:
        query = """
        MATCH (f:Finding {id: $finding_id})
        SET f.corroborating_sources = coalesce(f.corroborating_sources, [])
        WITH f
        WHERE NOT $source_name IN f.corroborating_sources
        SET f.corroborating_sources = f.corroborating_sources + $source_name
        WITH f
        WHERE size(f.corroborating_sources) >= 2
          AND f.status = 'AI_VALIDATED'
        SET f.status = 'CORROBORATED'
        RETURN f
        """
        result = await self.session.run(query, finding_id=finding_id, source_name=source_name)
        record = await result.single()
        if not record:
            res = await self.session.run("MATCH (f:Finding {id: $finding_id}) RETURN f", finding_id=finding_id)
            rec = await res.single()
            if not rec:
                raise ValueError("Finding not found")
            return Finding(**rec["f"])
        return Finding(**record["f"])

    def _derive_endpoint_pattern(self, url: str) -> str:
        parts = url.split('/')
        new_parts = []
        for part in parts:
            if re.match(r'^\d+$', part) or re.match(r'^[0-9a-fA-F-]{36}$', part):
                new_parts.append('{id}')
            else:
                new_parts.append(part)
        return '/'.join(new_parts)

    async def mark_reviewed(self, finding_id: str, human_decision: str, reviewer_note: str) -> Finding:
        status = FindingStatus.HUMAN_CONFIRMED if human_decision == "confirmed" else FindingStatus.FALSE_POSITIVE
        query = """
        MATCH (f:Finding {id: $finding_id})
        SET f.status = $status, f.reviewer_note = $note
        RETURN f
        """
        result = await self.session.run(query, finding_id=finding_id, status=status.value, note=reviewer_note)
        record = await result.single()
        if not record:
             raise ValueError("Finding not found")

        finding_data = record["f"]

        if human_decision == "false_positive":
            url_query = """
            MATCH (f:Finding {id: $finding_id})<-[:HAS_FINDING]-(target)
            OPTIONAL MATCH (target)-[:HAS_PARAMETER]-(e:Endpoint)
            WITH coalesce(e, target) as endpoint, f, target
            MATCH (endpoint)<-[:HAS_ENDPOINT]-(h:Host)<-[:IN_SCOPE]-(i:Investigation)
            RETURN endpoint.url as url, target.name as param_name, i.id as investigation_id
            """
            url_res = await self.session.run(url_query, finding_id=finding_id)
            url_rec = await url_res.single()
            if url_rec:
                url = url_rec["url"]
                param_name = url_rec.get("param_name")
                investigation_id = url_rec["investigation_id"]

                pattern = self._derive_endpoint_pattern(url)
                fp_id = generate_id(investigation_id, finding_data["vuln_type"], pattern, param_name)

                fp_query = """
                MATCH (i:Investigation {id: $investigation_id}), (f:Finding {id: $finding_id})
                MERGE (fp:FalsePositivePattern {id: $fp_id})
                ON CREATE SET fp.vuln_type = $vuln_type, fp.endpoint_pattern = $pattern,
                              fp.parameter_name = $param_name, fp.reason = $reason,
                              fp.created_at = $now
                MERGE (i)-[:HAS_FP_PATTERN]->(fp)
                MERGE (f)-[:MATCHES_FP_PATTERN]->(fp)
                """
                await self.session.run(fp_query, investigation_id=investigation_id, finding_id=finding_id,
                                      fp_id=fp_id, vuln_type=finding_data["vuln_type"],
                                      pattern=pattern, param_name=param_name,
                                      reason=reviewer_note, now=datetime.utcnow().isoformat() + "Z")

        return Finding(**finding_data)

    async def get_findings_needing_review(self, investigation_id: str, threshold: float = 0.7) -> List[Finding]:
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:IN_SCOPE]->(h:Host)
        OPTIONAL MATCH (h)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_FINDING]->(f1:Finding)
        OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(param:Parameter)-[:HAS_FINDING]->(f2:Finding)
        WITH collect(f1) + collect(f2) as findings
        UNWIND findings as f
        WITH DISTINCT f
        WHERE f IS NOT NULL
          AND (f.status = 'UNCONFIRMED' OR f.status = 'AI_VALIDATED')
          AND (f.ai_confidence < $threshold OR f.ai_confidence IS NULL)
        WITH f,
             CASE f.severity
               WHEN 'critical' THEN 4
               WHEN 'high' THEN 3
               WHEN 'medium' THEN 2
               WHEN 'low' THEN 1
               ELSE 0
             END as sev_score
        ORDER BY sev_score DESC, f.ai_confidence ASC
        RETURN f
        """
        result = await self.session.run(query, investigation_id=investigation_id, threshold=threshold)
        findings = []
        async for record in result:
            findings.append(Finding(**record["f"]))
        return findings

    async def check_known_false_positive_patterns(self, investigation_id: str, vuln_type: str, endpoint: str, parameter: Optional[str] = None) -> List[FalsePositivePattern]:
        pattern = self._derive_endpoint_pattern(endpoint)
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:HAS_FP_PATTERN]->(fp:FalsePositivePattern)
        WHERE fp.vuln_type = $vuln_type AND fp.endpoint_pattern = $pattern
        """
        if parameter:
            query += " AND fp.parameter_name = $parameter"
        else:
            query += " AND fp.parameter_name IS NULL"

        query += " RETURN fp"

        result = await self.session.run(query, investigation_id=investigation_id, vuln_type=vuln_type, pattern=pattern, parameter=parameter)
        patterns = []
        async for record in result:
            patterns.append(FalsePositivePattern(**record["fp"]))
        return patterns

    async def link_finding_to_cve(self, finding_id: str, cve: CVECreate) -> None:
        c_id = generate_id(cve.cve_id)
        query = """
        MATCH (f:Finding {id: $finding_id})
        MERGE (c:CVE {id: $c_id})
        SET c.cve_id = $cve_id, c.cvss_score = $cvss_score, c.description = $description
        MERGE (f)-[:MATCHES_CVE]->(c)
        """
        await self.session.run(query, finding_id=finding_id, c_id=c_id, cve_id=cve.cve_id,
                              cvss_score=cve.cvss_score, description=cve.description)

    @retry_on_transient_error()
    async def get_attack_surface(self, investigation_id: str) -> Dict[str, Any]:
        # Use APOC to reliably fetch the connected subgraph up to 5 levels
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        CALL apoc.path.subgraphAll(i, {
            maxLevel: 5,
            relationshipFilter: ''
        })
        YIELD nodes, relationships
        RETURN nodes, relationships, i
        """
        result = await self.session.run(query, investigation_id=investigation_id)
        record = await result.single()

        nodes = []
        links = []

        if record:
            # apoc.path.subgraphAll includes the start node in 'nodes'
            for n in record["nodes"]:
                # Handle both real Neo4j nodes and mock nodes in tests
                properties = dict(n.items()) if hasattr(n, 'items') else dict(n)
                labels = list(n.labels)
                # Map Investigation label back to Program if any legacy components require it
                if "Investigation" in labels:
                    labels.append("Program")
                nodes.append({
                    "id": n["id"],
                    "labels": labels,
                    "properties": properties
                })

            for r in record["relationships"]:
                links.append({
                    "source": r.start_node["id"],
                    "target": r.end_node["id"],
                    "type": r.type
                })

        return {"nodes": nodes, "links": links}

    async def get_findings_by_severity(self, investigation_id: str, min_severity: str) -> List[Finding]:
        severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_val = severity_map.get(min_severity.lower(), 0)

        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:IN_SCOPE]->(h:Host)
        OPTIONAL MATCH (h)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_FINDING]->(f1:Finding)
        OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(param:Parameter)-[:HAS_FINDING]->(f2:Finding)
        WITH collect(f1) + collect(f2) as findings
        UNWIND findings as f
        WITH DISTINCT f
        WHERE f IS NOT NULL AND f.status <> 'DUPLICATE'
        RETURN f
        """
        result = await self.session.run(query, investigation_id=investigation_id)
        findings = []
        async for record in result:
            f = record["f"]
            if severity_map.get(f["severity"].lower(), 0) >= min_val:
                findings.append(Finding(**f))
        return findings

    async def find_attack_paths(self, host_id: str) -> List[Dict[str, Any]]:
        query = """
        MATCH (h:Host {id: $host_id})
        MATCH p = (h)-[*1..5]->(f:Finding)
        RETURN p
        """
        result = await self.session.run(query, host_id=host_id)
        paths = []
        async for record in result:
            path = record["p"]
            paths.append({
                "nodes": [{"id": n["id"], "labels": list(n.labels)} for n in path.nodes],
                "relationships": [{"type": r.type} for r in path.relationships]
            })
        return paths

    async def delete_investigation_recursive(self, investigation_id: str) -> None:
        # Delete Investigation node and everything reachable ONLY through it.
        # shared nodes like Tool or CVE with other incoming rels should be preserved.
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        // Find all reachable nodes
        OPTIONAL MATCH (i)-[*1..10]->(n)
        WITH i, collect(DISTINCT n) as reachable_nodes
        UNWIND reachable_nodes + [i] as node

        // For each node, check if it has any incoming rel from a node NOT in reachable_nodes
        OPTIONAL MATCH (other)-[r]->(node)
        WHERE NOT other IN reachable_nodes AND NOT other = i
        WITH node, count(r) as external_rels
        WHERE external_rels = 0
        DETACH DELETE node
        """
        await self.session.run(query, investigation_id=investigation_id)

    # Legacy Program deletion fallback
    async def delete_program_recursive(self, program_id: str) -> None:
        await self.delete_investigation_recursive(program_id)

    async def create_recon_session(self, session_id: str, investigation_id: str, domains: List[str], status: str) -> ReconSession:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MERGE (s:ReconSession {id: $id})
        ON CREATE SET s.investigation_id = $investigation_id, s.domains = $domains, s.status = $status, s.started_at = $now
        MERGE (i)-[:HAD_RECON_SESSION]->(s)
        RETURN s
        """
        result = await self.session.run(query, id=session_id, investigation_id=investigation_id, domains=domains, status=status, now=now)
        record = await result.single()
        return ReconSession(**record["s"])

    async def update_recon_session_status(self, session_id: str, status: str, tool_results: Optional[dict] = None) -> ReconSession:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (s:ReconSession {id: $id})
        SET s.status = $status
        """
        if status in ["completed", "partial", "failed"]:
            query += ", s.completed_at = $now"
        if tool_results:
            query += ", s.tool_results = $tool_results"

        query += " RETURN s"

        # Serialize tool_results to JSON string for Neo4j if it's a dict
        results_json = json.dumps(tool_results) if tool_results else None

        result = await self.session.run(query, id=session_id, status=status, now=now, tool_results=results_json)
        record = await result.single()
        if record is None:
             raise ValueError(f"ReconSession {session_id} not found — cannot update status")

        data = dict(record["s"])
        if data.get("tool_results"):
             data["tool_results"] = json.loads(data["tool_results"])
        return ReconSession(**data)

    @retry_on_transient_error()
    async def list_recon_sessions(self, investigation_id: str) -> List[ReconSession]:
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:HAD_RECON_SESSION]->(s:ReconSession)
        RETURN s ORDER BY s.started_at DESC
        """
        result = await self.session.run(query, investigation_id=investigation_id)
        sessions = []
        async for record in result:
            data = dict(record["s"])
            if data.get("tool_results"):
                 data["tool_results"] = json.loads(data["tool_results"])
            sessions.append(ReconSession(**data))
        return sessions

    @retry_on_transient_error()
    async def get_recon_session(self, session_id: str) -> Optional[ReconSession]:
        query = "MATCH (s:ReconSession {id: $id}) RETURN s"
        result = await self.session.run(query, id=session_id)
        record = await result.single()
        if not record:
            return None
        data = dict(record["s"])
        if data.get("tool_results"):
             data["tool_results"] = json.loads(data["tool_results"])
        return ReconSession(**data)

    async def deduplicate_findings(self, investigation_id: str) -> int:
        # Instead of physically merging nodes (which might lose historical data or confuse relationships),
        # we mark the older ones as DUPLICATE.
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:IN_SCOPE]->(h:Host)-[:HAS_ENDPOINT]->(e:Endpoint)
        MATCH (e)-[:HAS_FINDING]->(f:Finding)
        WITH e, f.vuln_type as vtype, collect(f) as findings
        WHERE size(findings) > 1
        UNWIND tail(findings) as duplicate
        SET duplicate.status = 'DUPLICATE'
        RETURN count(duplicate) as merged_count
        """
        query_param = """
        MATCH (i:Investigation {id: $investigation_id})-[:IN_SCOPE]->(h:Host)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_PARAMETER]->(param:Parameter)
        MATCH (param)-[:HAS_FINDING]->(f:Finding)
        WITH param, f.vuln_type as vtype, collect(f) as findings
        WHERE size(findings) > 1
        UNWIND tail(findings) as duplicate
        SET duplicate.status = 'DUPLICATE'
        RETURN count(duplicate) as merged_count
        """

        res1 = await self.session.run(query, investigation_id=investigation_id)
        rec1 = await res1.single()
        count1 = rec1["merged_count"] if rec1 else 0

        res2 = await self.session.run(query_param, investigation_id=investigation_id)
        rec2 = await res2.single()
        count2 = rec2["merged_count"] if rec2 else 0

        return count1 + count2

    async def create_agent_session(self, session_id: str, investigation_id: str, status: str, iteration_count: int = 0, tools_used: List[str] = [], reasoning_log: List[str] = []) -> AgentSession:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (i:Investigation {id: $investigation_id})
        MERGE (s:AgentSession {id: $id})
        ON CREATE SET s.investigation_id = $investigation_id, s.status = $status, s.started_at = $now, s.iteration_count = $iteration_count, s.tools_used = $tools_used, s.reasoning_log = $reasoning_log
        MERGE (i)-[:HAD_AGENT_SESSION]->(s)
        RETURN s
        """
        result = await self.session.run(query, id=session_id, investigation_id=investigation_id, status=status, now=now, iteration_count=iteration_count, tools_used=tools_used, reasoning_log=reasoning_log)
        record = await result.single()
        if record is None:
            fallback_query = """
            MERGE (s:AgentSession {id: $id})
            ON CREATE SET s.investigation_id = $investigation_id, s.status = $status, s.started_at = $now, s.iteration_count = $iteration_count, s.tools_used = $tools_used, s.reasoning_log = $reasoning_log
            RETURN s
            """
            result = await self.session.run(fallback_query, id=session_id, investigation_id=investigation_id, status=status, now=now, iteration_count=iteration_count, tools_used=tools_used, reasoning_log=reasoning_log)
            record = await result.single()
        return AgentSession(**record["s"])

    async def update_agent_session_status(self, session_id: str, status: str, iteration_count: Optional[int] = None, tools_used: Optional[List[str]] = None, final_report: Optional[str] = None, reasoning_log: Optional[List[str]] = None) -> AgentSession:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (s:AgentSession {id: $id})
        SET s.status = $status
        """
        if status in ["completed", "failed", "stopped", "interrupted"]:
            query += ", s.completed_at = $now"
        if iteration_count is not None:
            query += ", s.iteration_count = $iteration_count"
        if tools_used is not None:
            query += ", s.tools_used = $tools_used"
        if final_report is not None:
            query += ", s.final_report = $final_report"
        if reasoning_log is not None:
            query += ", s.reasoning_log = $reasoning_log"

        query += " RETURN s"

        result = await self.session.run(query, id=session_id, status=status, now=now, iteration_count=iteration_count, tools_used=tools_used, final_report=final_report, reasoning_log=reasoning_log)
        record = await result.single()
        if record is None:
             raise ValueError(f"AgentSession {session_id} not found — cannot update status")

        return AgentSession(**record["s"])

    @retry_on_transient_error()
    async def list_agent_sessions(self, investigation_id: str) -> List[AgentSession]:
        query = """
        MATCH (i:Investigation {id: $investigation_id})-[:HAD_AGENT_SESSION]->(s:AgentSession)
        RETURN s ORDER BY s.started_at DESC
        """
        result = await self.session.run(query, investigation_id=investigation_id)
        sessions = []
        async for record in result:
            sessions.append(AgentSession(**record["s"]))
        return sessions

    @retry_on_transient_error()
    async def get_agent_session(self, session_id: str) -> Optional[AgentSession]:
        query = "MATCH (s:AgentSession {id: $id}) RETURN s"
        result = await self.session.run(query, id=session_id)
        record = await result.single()
        if not record:
            return None
        return AgentSession(**record["s"])

    async def cleanup_orphaned_agent_sessions(self) -> int:
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (s:AgentSession {status: "running"})
        SET s.status = "interrupted", s.completed_at = $now
        RETURN count(s) as count
        """
        result = await self.session.run(query, now=now)
        record = await result.single()
        return record["count"] if record else 0

    @retry_on_transient_error()
    async def list_all_agent_sessions(self) -> List[AgentSession]:
        query = "MATCH (s:AgentSession) RETURN s ORDER BY s.started_at DESC"
        result = await self.session.run(query)
        sessions = []
        async for record in result:
            sessions.append(AgentSession(**record["s"]))
        return sessions
