from fastapi import APIRouter, HTTPException
from ..schemas import ReconRequest, ReconSessionStatus, ReconSessionResults
from ..orchestrator import orchestrator

router = APIRouter()

@router.post("/start", status_code=202)
async def start_recon(request: ReconRequest):
    session_id = orchestrator.start_session(request)
    return {"session_id": session_id}

@router.get("/{session_id}/status", response_model=ReconSessionStatus)
async def get_status(session_id: str):
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    return orchestrator.sessions[session_id]

@router.get("/{session_id}/results", response_model=ReconSessionResults)
async def get_results(session_id: str):
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    results = orchestrator.results.get(session_id, None)
    if results is None:
        from ..schemas import ToolResults
        results = ToolResults()

    return ReconSessionResults(session_id=session_id, results=results)
