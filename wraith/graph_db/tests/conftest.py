import pytest
import asyncio
from testcontainers.neo4j import Neo4jContainer
from neo4j import AsyncGraphDatabase
from app.config import settings

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def neo4j_container():
    with Neo4jContainer("neo4j:5-community") as neo4j:
        # Enable APOC
        # The testcontainer might not easily support setting env vars for plugins
        # but let's see if we can use it.
        # Actually Neo4jContainer has restricted support for some things.
        # Let's just set the auth.
        yield neo4j

@pytest.fixture(scope="session")
async def neo4j_driver(neo4j_container):
    uri = neo4j_container.get_connection_url()
    user = "neo4j"
    password = neo4j_container.password

    driver = AsyncGraphDatabase.driver(uri, auth=(user, password))

    # Override settings for tests
    settings.NEO4J_URI = uri
    settings.NEO4J_USER = user
    settings.NEO4J_PASSWORD = password

    yield driver
    await driver.close()

@pytest.fixture
async def neo4j_session(neo4j_driver):
    async with neo4j_driver.session() as session:
        yield session
        # Cleanup after each test
        await session.run("MATCH (n) DETACH DELETE n")
