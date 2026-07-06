from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from .api.routes import router
from .client import neo4j_client
from .repository import Neo4jRepository

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect to Neo4j and initialize DB
    await neo4j_client.connect()
    session = await neo4j_client.get_session()
    try:
        repo = Neo4jRepository(session)
        await repo.initialize_db()
    finally:
        await session.close()
    yield
    # Shutdown: Close Neo4j connection
    await neo4j_client.close()

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Wraith Graph API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")

@app.get("/health")
async def health_check(response: Response):
    is_healthy = await neo4j_client.verify_connectivity()
    if is_healthy:
        return {"status": "healthy", "database": "neo4j connected"}
    else:
        response.status_code = 503
        return {"status": "unhealthy", "database": "neo4j disconnected"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
