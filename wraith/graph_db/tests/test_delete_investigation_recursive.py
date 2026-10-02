import pytest
from app.repository import Neo4jRepository
from app.schema import InvestigationCreate, HostCreate


async def _count(session, pattern: str, **params) -> int:
    result = await session.run(pattern, **params)
    record = await result.single()
    return record["c"] if record else 0


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_removes_root_despite_inbound_scan_session(neo4j_session):
    """
    Regression: the root Investigation node used to survive deletion.

    delete_investigation_recursive applied the "no incoming relationships
    from outside the subgraph" test to the root as well as to its
    descendants. Every scanned investigation has an inbound -[:TARGETED]->
    edge from a ScanSession, and the traversal only walks outbound, so that
    edge always counted as external. external_rels was therefore 1 on the
    root, the root was filtered out by `WHERE external_rels = 0`, and
    nothing at all was deleted -- while the API answered
    {"status": "deleted"} and the panel showed a success toast.
    """
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    inv = await repo.create_investigation(
        InvestigationCreate(name="Delete Regression", target="example.com")
    )

    # Precondition: the inbound edge that used to protect the root.
    await neo4j_session.run(
        """
        MATCH (i:Investigation {id: $id})
        MERGE (s:ScanSession {id: 'ss-regression'})
        MERGE (s)-[:TARGETED]->(i)
        """,
        id=inv.id,
    )
    assert (
        await _count(
            neo4j_session,
            "MATCH (s:ScanSession)-[:TARGETED]->(i:Investigation {id: $id}) RETURN count(s) AS c",
            id=inv.id,
        )
        == 1
    ), "precondition: the investigation must have an inbound TARGETED edge"

    deleted = await repo.delete_investigation_recursive(inv.id)
    assert deleted > 0, "delete must actually remove nodes"

    assert (
        await _count(
            neo4j_session, "MATCH (i:Investigation {id: $id}) RETURN count(i) AS c", id=inv.id
        )
        == 0
    ), "investigation root survived deletion"

    assert (
        await _count(neo4j_session, "MATCH (s:ScanSession {id: 'ss-regression'}) RETURN count(s) AS c")
        == 0
    ), "the orphaned ScanSession should cascade with its investigation"


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_removes_exclusive_subgraph(neo4j_session):
    """Nodes reachable only through this investigation go with it."""
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    inv = await repo.create_investigation(
        InvestigationCreate(name="Subgraph Delete", target="exclusive.example.com")
    )
    host = await repo.upsert_host(HostCreate(value="exclusive.example.com"), inv.id)

    deleted = await repo.delete_investigation_recursive(inv.id)
    assert deleted > 0

    assert (
        await _count(neo4j_session, "MATCH (h:Host {id: $id}) RETURN count(h) AS c", id=host.id)
        == 0
    ), "a host reachable only via this investigation must be deleted"


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_preserves_nodes_shared_with_another_investigation(neo4j_session):
    """The shared-node rule the original comment described must still hold."""
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    keep = await repo.create_investigation(
        InvestigationCreate(name="Keep Me", target="shared.example.com")
    )
    drop = await repo.create_investigation(
        InvestigationCreate(name="Drop Me", target="shared.example.com")
    )

    # A globally-identified node both investigations point at. Tool ids are not
    # namespaced by investigation, which is exactly why this rule matters.
    tool_id = await repo.upsert_tool("shared-tool", "1.0")
    await neo4j_session.run(
        """
        MATCH (t:Tool {id: $tid}), (a:Investigation {id: $keep}), (b:Investigation {id: $drop})
        MERGE (a)-[:USES_TOOL]->(t)
        MERGE (b)-[:USES_TOOL]->(t)
        """,
        tid=tool_id,
        keep=keep.id,
        drop=drop.id,
    )

    await repo.delete_investigation_recursive(drop.id)

    assert (
        await _count(
            neo4j_session, "MATCH (i:Investigation {id: $id}) RETURN count(i) AS c", id=drop.id
        )
        == 0
    ), "the deleted investigation must be gone"

    assert (
        await _count(neo4j_session, "MATCH (t:Tool {id: $id}) RETURN count(t) AS c", id=tool_id)
        == 1
    ), "a node still referenced by another investigation must survive"

    assert (
        await _count(
            neo4j_session, "MATCH (i:Investigation {id: $id}) RETURN count(i) AS c", id=keep.id
        )
        == 1
    ), "the other investigation must be untouched"


@pytest.mark.asyncio(loop_scope="session")
async def test_delete_missing_investigation_is_a_noop(neo4j_session):
    """Deleting an unknown id must not raise or delete anything else."""
    repo = Neo4jRepository(neo4j_session)
    await repo.initialize_db()

    keep = await repo.create_investigation(
        InvestigationCreate(name="Untouched", target="untouched.example.com")
    )

    deleted = await repo.delete_investigation_recursive("does-not-exist")
    assert deleted == 0

    assert (
        await _count(
            neo4j_session, "MATCH (i:Investigation {id: $id}) RETURN count(i) AS c", id=keep.id
        )
        == 1
    )
