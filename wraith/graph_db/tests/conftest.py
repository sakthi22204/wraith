import pytest
import pytest_asyncio
from testcontainers.neo4j import Neo4jContainer
from neo4j import AsyncGraphDatabase
from app.config import settings

# These fixtures used bare @pytest.fixture on async generators. pytest-asyncio
# 1.x runs in strict mode, so an async fixture without pytest_asyncio.fixture is
# never set up: the tests ERROR with PytestRemovedIn9Warning instead of running.
# That is why this directory was excluded from run_tests.sh, and it meant
# test_api.py -- the only test that exercises the HTTP routes rather than the
# repository -- had not been running at all.

# No event_loop override: pytest-asyncio 1.x removed it, and overriding it either
# warns or does nothing depending on the version.


@pytest.fixture(scope="session")
def neo4j_container():
    # APOC has to be requested explicitly. get_program_graph() calls
    # apoc.path.subgraphAll, so without this the route fails at runtime with
    # ProcedureNotFound. The composed graph_db service sets the same variable,
    # which is why only the testcontainer was affected. The previous comment
    # here said "let's see if we can use it"; with_env is how.
    with Neo4jContainer("neo4j:5-community").with_env(
        "NEO4J_PLUGINS", '["apoc"]'
    ) as neo4j:
        yield neo4j


# loop_scope="session" on both the driver and the tests: an async Neo4j driver is
# bound to the loop that created it, so a session-scoped driver used from
# per-test loops fails with "got Future attached to a different loop".
@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def neo4j_driver(neo4j_container):
    uri = neo4j_container.get_connection_url()
    user = "neo4j"
    password = neo4j_container.password

    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    # Point the app at the container instead of the composed graph_db.
    settings.NEO4J_URI = uri
    settings.NEO4J_USER = user
    settings.NEO4J_PASSWORD = password

    yield driver
    await driver.close()


@pytest_asyncio.fixture(loop_scope="session")
async def neo4j_session(neo4j_driver):
    async with neo4j_driver.session() as session:
        yield session
        # Cleanup after each test
        await session.run("MATCH (n) DETACH DELETE n")