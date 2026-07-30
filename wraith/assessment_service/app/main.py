from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import httpx
from typing import Dict
from datetime import datetime

from .config import settings
from .schemas import AssessmentReport
from .services import AssessmentEngine

app = FastAPI(title="Wraith Assessment Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for assessment cache
assessments_db: Dict[str, AssessmentReport] = {}

@app.post("/api/v1/assessments/{investigation_id}", response_model=AssessmentReport)
async def perform_assessment(investigation_id: str):
    headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
    graph_url = f"{settings.GRAPH_DB_URL}/investigations/{investigation_id}/graph"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(graph_url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch graph from Graph DB: {resp.text}")
            graph_data = resp.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to communicate with Graph DB: {e}")

    try:
        report = AssessmentEngine.generate_report(investigation_id, graph_data)
        assessments_db[investigation_id] = report
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to compute assessment report: {e}")

@app.get("/api/v1/assessments/{investigation_id}", response_model=AssessmentReport)
async def get_assessment(investigation_id: str):
    if investigation_id in assessments_db:
        return assessments_db[investigation_id]

    # Trigger compute on-the-fly if not cached
    return await perform_assessment(investigation_id)

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)
