import hashlib
import json
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from neo4j import AsyncSession
from .schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVE, CVECreate, Node, Link, GraphResponse
)

def generate_id(*args) -> str:
    seed = ":".join(str(arg) for arg in args)
    return hashlib.sha256(seed.encode()).hexdigest()

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
            "CREATE CONSTRAINT scansession_id IF NOT EXISTS FOR (s:ScanSession) REQUIRE s.id IS UNIQUE"
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

    async def create_scan_session(self, program_id: str) -> dict:
        s_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        query = """
        MATCH (p:Program {id: $program_id})
        MERGE (s:ScanSession {id: $s_id})
        ON CREATE SET s.started_at = $started_at, s.status = "running"
        MERGE (s)-[:TARGETED]->(p)
        RETURN s
        """
        result = await self.session.run(query, program_id=program_id, s_id=s_id, started_at=now)
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

    async def create_program(self, program: ProgramCreate) -> Program:
        p_id = generate_id(program.name)
        now = datetime.utcnow().isoformat()
        query = """
        MERGE (p:Program {id: $id})
        ON CREATE SET p.name = $name, p.platform = $platform, p.scope_domains = $scope_domains, p.created_at = $created_at
        RETURN p
        """
        result = await self.session.run(query, id=p_id, name=program.name, platform=program.platform,
                                      scope_domains=program.scope_domains, created_at=now)
        record = await result.single()
        return Program(**record["p"])

    async def upsert_host(self, host: HostCreate, program_id: str) -> Host:
        h_id = generate_id(host.value)
        now = datetime.utcnow().isoformat()
        query = """
        MATCH (p:Program {id: $program_id})
        MERGE (h:Host {id: $h_id})
        ON CREATE SET h.value = $value, h.first_seen = $now, h.last_seen = $now
        ON MATCH SET h.last_seen = $now
        MERGE (p)-[:IN_SCOPE]->(h)
        RETURN h
        """
        result = await self.session.run(query, program_id=program_id, h_id=h_id, value=host.value, now=now)
        record = await result.single()
        return Host(**record["h"])

    async def upsert_port(self, port: PortCreate, host_id: str) -> Port:
        # We need protocol for uniqueness
        p_id = generate_id(host_id, port.number, port.protocol)
        query = """
        MATCH (h:Host {id: $host_id})
        MERGE (p:Port {id: $p_id})
        SET p.number = $number, p.protocol = $protocol, p.state = $state
        MERGE (h)-[:HAS_PORT]->(p)
        RETURN p
        """
        result = await self.session.run(query, host_id=host_id, p_id=p_id, number=port.number,
                                      protocol=port.protocol, state=port.state)
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
        ON CREATE SET e.url = $url, e.method = $method, e.first_seen = $now
        MERGE (h)-[:HAS_ENDPOINT]->(e)
        RETURN e
        """
        result = await self.session.run(query, host_id=host_id, e_id=e_id, url=endpoint.url,
                                      method=endpoint.method, now=now)
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
        # Deterministic ID based on vuln_type and target
        f_id = generate_id(finding.vuln_type, finding.target_id)
        # Using Z suffix for UTC as it's common practice for ISO 8601 UTC
        now_utc = finding.discovered_at.isoformat() + "Z"
        query = f"""
        MATCH (t:{finding.target_type.capitalize()} {{id: $target_id}})
        MERGE (f:Finding {{id: $f_id}})
        SET f.vuln_type = $vuln_type, f.severity = $severity, f.confidence = $confidence,
            f.status = $status, f.description = $description, f.discovered_at = $discovered_at
        MERGE (t)-[:HAS_FINDING]->(f)
        RETURN f
        """
        result = await self.session.run(query, target_id=finding.target_id, f_id=f_id, vuln_type=finding.vuln_type,
                                      severity=finding.severity, confidence=finding.confidence,
                                      status=finding.status, description=finding.description,
                                      discovered_at=now_utc)
        record = await result.single()
        return Finding(**record["f"])

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

    async def get_attack_surface(self, program_id: str) -> Dict[str, Any]:
        query = """
        MATCH (p:Program {id: $program_id})
        MATCH (p)-[*1..5]-(n)
        WITH DISTINCT n
        MATCH (n)-[r]-(m)
        WHERE m IN [(p)-[*1..5]-(x) | x] OR m = p
        RETURN collect(DISTINCT n) as nodes, collect(DISTINCT r) as rels, p
        """
        # Note: This might need refinement for large graphs
        result = await self.session.run(query, program_id=program_id)
        record = await result.single()

        nodes = []
        links = []

        if record:
            program_node = record["p"]
            nodes.append({
                "id": program_node["id"],
                "labels": list(program_node.labels),
                "properties": dict(program_node)
            })

            for n in record["nodes"]:
                nodes.append({
                    "id": n["id"],
                    "labels": list(n.labels),
                    "properties": dict(n)
                })

            for r in record["rels"]:
                links.append({
                    "source": r.start_node["id"],
                    "target": r.end_node["id"],
                    "type": r.type
                })

        return {"nodes": nodes, "links": links}

    async def get_findings_by_severity(self, program_id: str, min_severity: str) -> List[Finding]:
        # Simple severity mapping
        severity_map = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_val = severity_map.get(min_severity.lower(), 0)

        query = """
        MATCH (p:Program {id: $program_id})-[:IN_SCOPE]->(h:Host)
        OPTIONAL MATCH (h)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_FINDING]->(f1:Finding)
        OPTIONAL MATCH (e)-[:HAS_PARAMETER]->(param:Parameter)-[:HAS_FINDING]->(f2:Finding)
        WITH collect(f1) + collect(f2) as findings
        UNWIND findings as f
        WITH DISTINCT f
        WHERE f IS NOT NULL
        RETURN f
        """
        # This query might be slow; also need to handle severity filtering in Cypher or Python
        # Let's try to do it in Cypher if we can define an order

        result = await self.session.run(query, program_id=program_id)
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

    async def deduplicate_findings(self, program_id: str) -> int:
        # Merge findings with same vuln_type+endpoint+parameter
        # Actually our generate_id(vuln_type, target_id) already handles this if we use MERGE.
        # But if there are findings created without deterministic IDs, we'd need this.
        # Requirement says: "merge findings with same vuln_type+endpoint+parameter"

        # Let's implement a query that finds duplicates and merges them.
        # Since we use MERGE on f_id, we might already be "deduplicated".
        # However, if target_id is different but they represent same logical endpoint...

        # A more complex dedupe might be needed if we don't have perfect IDs.
        # Given the requirements, I'll provide a Cypher query that merges based on the criteria.

        query = """
        MATCH (p:Program {id: $program_id})-[:IN_SCOPE]->(h:Host)-[:HAS_ENDPOINT]->(e:Endpoint)
        MATCH (e)-[:HAS_FINDING]->(f:Finding)
        WITH e, f.vuln_type as vtype, collect(f) as findings
        WHERE size(findings) > 1
        CALL apoc.refactor.mergeNodes(findings, {properties: "combine", mergeRels: true})
        YIELD node
        RETURN count(node) as merged_count
        """
        # And for parameters
        query_param = """
        MATCH (p:Program {id: $program_id})-[:IN_SCOPE]->(h:Host)-[:HAS_ENDPOINT]->(e:Endpoint)-[:HAS_PARAMETER]->(param:Parameter)
        MATCH (param)-[:HAS_FINDING]->(f:Finding)
        WITH param, f.vuln_type as vtype, collect(f) as findings
        WHERE size(findings) > 1
        CALL apoc.refactor.mergeNodes(findings, {properties: "combine", mergeRels: true})
        YIELD node
        RETURN count(node) as merged_count
        """

        res1 = await self.session.run(query, program_id=program_id)
        rec1 = await res1.single()
        count1 = rec1["merged_count"] if rec1 else 0

        res2 = await self.session.run(query_param, program_id=program_id)
        rec2 = await res2.single()
        count2 = rec2["merged_count"] if rec2 else 0

        return count1 + count2
