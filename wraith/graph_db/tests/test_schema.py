import pytest
from app.repository import Neo4jRepository

@pytest.mark.asyncio
async def test_constraints_created(neo4j_session):
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    # Check if constraints exist
    result = await neo4j_session.run("SHOW CONSTRAINTS")
    constraints = [record["name"] for record in await result.data()]

    expected_constraints = [
        "program_id", "host_id", "port_id", "service_id",
        "endpoint_id", "parameter_id", "finding_id",
        "cve_id", "tool_id", "scansession_id"
    ]

    for ec in expected_constraints:
        assert ec in constraints
