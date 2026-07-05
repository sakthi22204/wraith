import hashlib
import json
import uuid
import re
from datetime import datetime
from typing import List, Optional, Dict, Any
from neo4j import AsyncSession
from .schema import (
    Program, ProgramCreate, Host, HostCreate, Port, PortCreate,
    Service, ServiceCreate, Endpoint, EndpointCreate, Parameter, ParameterCreate,
    Finding, FindingCreate, CVE, CVECreate, Node, Link, GraphResponse,
    FindingStatus, FalsePositivePattern, FalsePositivePatternCreate
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
            "CREATE CONSTRAINT scansession_id IF NOT EXISTS FOR (s:ScanSession) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT fppattern_id IF NOT EXISTS FOR (f:FalsePositivePattern) REQUIRE f.id IS UNIQUE"
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
        p_id = generate_id(program.name, program.platform)
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
        f_id = generate_id(finding.vuln_type, finding.target_id)
        now_utc = finding.discovered_at.isoformat() + "Z"
        query = f"""
        MATCH (t:{finding.target_type.capitalize()} {{id: $target_id}})
        MERGE (f:Finding {{id: $f_id}})
        SET f.vuln_type = $vuln_type, f.severity = $severity, f.confidence = $confidence,
            f.status = $status, f.description = $description, f.discovered_at = $discovered_at,
            f.ai_confidence = $ai_confidence, f.ai_reasoning = $ai_reasoning,
            f.corroborating_sources = $corroborating_sources,
            f.cvss_vector = $cvss_vector, f.evidence = $evidence
        MERGE (t)-[:HAS_FINDING]->(f)
        RETURN f
        """
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
            WITH coalesce(e, target) as endpoint, f
            MATCH (endpoint)<-[:HAS_ENDPOINT]-(h:Host)<-[:IN_SCOPE]-(p:Program)
            RETURN endpoint.url as url, target.name as param_name, p.id as program_id
            """
            url_res = await self.session.run(url_query, finding_id=finding_id)
            url_rec = await url_res.single()
            if url_rec:
                url = url_rec["url"]
                param_name = url_rec["param_name"] if "name" in url_rec else None
                program_id = url_rec["program_id"]

                pattern = self._derive_endpoint_pattern(url)
                fp_id = generate_id(program_id, finding_data["vuln_type"], pattern, param_name)

                fp_query = """
                MATCH (p:Program {id: $program_id}), (f:Finding {id: $finding_id})
                MERGE (fp:FalsePositivePattern {id: $fp_id})
                ON CREATE SET fp.vuln_type = $vuln_type, fp.endpoint_pattern = $pattern,
                              fp.parameter_name = $param_name, fp.reason = $reason,
                              fp.created_at = $now
                MERGE (p)-[:HAS_FP_PATTERN]->(fp)
                MERGE (f)-[:MATCHES_FP_PATTERN]->(fp)
                """
                await self.session.run(fp_query, program_id=program_id, finding_id=finding_id,
                                      fp_id=fp_id, vuln_type=finding_data["vuln_type"],
                                      pattern=pattern, param_name=param_name,
                                      reason=reviewer_note, now=datetime.utcnow().isoformat() + "Z")

        return Finding(**finding_data)

    async def get_findings_needing_review(self, program_id: str, threshold: float = 0.7) -> List[Finding]:
        query = """
        MATCH (p:Program {id: $program_id})-[:IN_SCOPE]->(h:Host)
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
        result = await self.session.run(query, program_id=program_id, threshold=threshold)
        findings = []
        async for record in result:
            findings.append(Finding(**record["f"]))
        return findings

    async def check_known_false_positive_patterns(self, program_id: str, vuln_type: str, endpoint: str, parameter: Optional[str] = None) -> List[FalsePositivePattern]:
        pattern = self._derive_endpoint_pattern(endpoint)
        query = """
        MATCH (p:Program {id: $program_id})-[:HAS_FP_PATTERN]->(fp:FalsePositivePattern)
        WHERE fp.vuln_type = $vuln_type AND fp.endpoint_pattern = $pattern
        """
        if parameter:
            query += " AND fp.parameter_name = $parameter"
        else:
            query += " AND fp.parameter_name IS NULL"

        query += " RETURN fp"

        result = await self.session.run(query, program_id=program_id, vuln_type=vuln_type, pattern=pattern, parameter=parameter)
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

    async def get_attack_surface(self, program_id: str) -> Dict[str, Any]:
        query = """
        MATCH (p:Program {id: $program_id})
        MATCH (p)-[*1..5]-(n)
        WITH DISTINCT n
        MATCH (n)-[r]-(m)
        WHERE m IN [(p)-[*1..5]-(x) | x] OR m = p
        RETURN collect(DISTINCT n) as nodes, collect(DISTINCT r) as rels, p
        """
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
        query = """
        MATCH (p:Program {id: $program_id})-[:IN_SCOPE]->(h:Host)-[:HAS_ENDPOINT]->(e:Endpoint)
        MATCH (e)-[:HAS_FINDING]->(f:Finding)
        WITH e, f.vuln_type as vtype, collect(f) as findings
        WHERE size(findings) > 1
        CALL apoc.refactor.mergeNodes(findings, {properties: "combine", mergeRels: true})
        YIELD node
        RETURN count(node) as merged_count
        """
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
