from contextlib import asynccontextmanager
from fastapi import FastAPI
from .api.routes import router
from .graph_client import graph_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await graph_client.close()

app = FastAPI(title="Wraith Recon Orchestrator", lifespan=lifespan)

app.include_router(router, prefix="/api/v1/recon")

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
