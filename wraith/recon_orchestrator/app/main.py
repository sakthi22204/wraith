from contextlib import asynccontextmanager
from fastapi import FastAPI
from .api.routes import router
from .graph_client import graph_client
from .config import settings, validate_startup_secrets

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Before anything is served. This service's POST /recon/start spawns tool
    # containers on the host Docker socket, so a blank or published broker token
    # is not a degraded mode, it is an open door. Refuse to come up instead.
    validate_startup_secrets(settings)
    yield
    await graph_client.close()

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="Wraith Recon Orchestrator", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1/recon")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
