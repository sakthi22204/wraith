from neo4j import AsyncGraphDatabase
from .config import settings

class Neo4jClient:
    def __init__(self):
        self.driver = None

    async def connect(self):
        if not self.driver:
            self.driver = AsyncGraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                max_connection_pool_size=settings.POOL_MAX_SIZE,
                connection_timeout=settings.CONNECTION_TIMEOUT
            )

    async def close(self):
        if self.driver:
            await self.driver.close()
            self.driver = None

    async def get_session(self):
        if not self.driver:
            await self.connect()
        return self.driver.session(database=settings.NEO4J_DATABASE)

    async def verify_connectivity(self):
        if not self.driver:
            await self.connect()
        try:
            await self.driver.verify_connectivity()
            return True
        except Exception:
            return False

neo4j_client = Neo4jClient()
