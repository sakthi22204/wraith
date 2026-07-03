import pytest
from datetime import datetime
from app.repository import Neo4jRepository
from app.schema import ProgramCreate, HostCreate, PortCreate, EndpointCreate, FindingCreate

@pytest.mark.asyncio
async def test_program_creation_and_idempotency(neo4j_session):
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    prog_data = ProgramCreate(name="Bug Bounty", platform="HackerOne", scope_domains=["example.com"])

    # First creation
    prog1 = await repo.create_program(prog_data)
    assert prog1.name == "Bug Bounty"

    # Second creation (idempotency check)
    prog2 = await repo.create_program(prog_data)
    assert prog1.id == prog2.id

    # Verify only one node exists
    result = await neo4j_session.run("MATCH (p:Program) RETURN count(p) as count")
    record = await result.single()
    assert record["count"] == 1

@pytest.mark.asyncio
async def test_host_upsert_and_idempotency(neo4j_session):
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    prog = await repo.create_program(ProgramCreate(name="Test", platform="Test", scope_domains=[]))

    host_data = HostCreate(value="1.2.3.4")

    # First upsert
    host1 = await repo.upsert_host(host_data, prog.id)
    assert host1.value == "1.2.3.4"

    # Second upsert
    host2 = await repo.upsert_host(host_data, prog.id)
    assert host1.id == host2.id

    # Verify count
    result = await neo4j_session.run("MATCH (h:Host) RETURN count(h) as count")
    record = await result.single()
    assert record["count"] == 1

@pytest.mark.asyncio
async def test_complex_graph_and_path(neo4j_session):
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    prog = await repo.create_program(ProgramCreate(name="Target", platform="Bugcrowd"))
    host = await repo.upsert_host(HostCreate(value="api.example.com"), prog.id)
    endpoint = await repo.upsert_endpoint(EndpointCreate(url="/login", method="POST"), host.id)
    finding = await repo.create_finding(
        FindingCreate(vuln_type="SQLi", severity="critical", confidence="high", status="open",
                      description="DB leak", target_id=endpoint.id, target_type="endpoint")
    )

    # Verify attack surface
    surface = await repo.get_attack_surface(prog.id)
    assert len(surface["nodes"]) >= 4 # Program, Host, Endpoint, Finding

    # Verify attack paths
    paths = await repo.find_attack_paths(host.id)
    assert len(paths) > 0
    assert paths[0]["nodes"][-1]["labels"] == ["Finding"]

@pytest.mark.asyncio
async def test_deduplication(neo4j_session):
    # This might be tricky if we use deterministic IDs, as duplicates are hard to create
    # But let's verify that re-creating a finding with same criteria doesn't add nodes.
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    prog = await repo.create_program(ProgramCreate(name="Dedupe Test", platform="X"))
    host = await repo.upsert_host(HostCreate(value="dedupe.me"), prog.id)
    endpoint = await repo.upsert_endpoint(EndpointCreate(url="/", method="GET"), host.id)

    finding_data = FindingCreate(vuln_type="XSS", severity="high", confidence="high",
                                 status="new", description="XSS", target_id=endpoint.id, target_type="endpoint")

    await repo.create_finding(finding_data)
    await repo.create_finding(finding_data)

    result = await neo4j_session.run("MATCH (f:Finding) RETURN count(f) as count")
    record = await result.single()
    assert record["count"] == 1
