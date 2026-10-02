from contextlib import asynccontextmanager
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import httpx
from typing import Dict
from datetime import datetime

from .auth import require_admin_token
from .config import settings, validate_startup_secrets
from .schemas import AssessmentReport
from .services import AssessmentEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Before anything is served: the assessment route reads the whole graph, so a
    # blank or published admin token is an unauthenticated view of it.
    validate_startup_secrets(settings)
    yield


app = FastAPI(title="Wraith Assessment Service", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for assessment cache
assessments_db: Dict[str, AssessmentReport] = {}

# Mutating: pulls the whole investigation graph and writes this service's
# cache. Gated like any other write.
@app.post("/api/v1/assessments/{investigation_id}", response_model=AssessmentReport,
          dependencies=[Depends(require_admin_token)])
async def perform_assessment(investigation_id: str):
    headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
    graph_url = f"{settings.GRAPH_DB_URL}/investigations/{investigation_id}/graph"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(graph_url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch graph from Graph DB: {resp.text}")
            graph_data = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to communicate with Graph DB: {e}")

    try:
        report = AssessmentEngine.generate_report(investigation_id, graph_data)
        assessments_db[investigation_id] = report
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute assessment report: {e}")

@app.get("/api/v1/assessments/{investigation_id}", response_model=AssessmentReport)
async def get_assessment(investigation_id: str, authorization: str = Header(None)):
    if investigation_id in assessments_db:
        return assessments_db[investigation_id]

    # Trigger compute on-the-fly if not cached. perform_assessment carries the
    # admin dependency, and calling it directly here is the uncached path, so the
    # token is required too rather than inherited from the GET route.
    await require_admin_token(authorization)
    return await perform_assessment(investigation_id)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)