from fastapi import APIRouter, HTTPException, Query, Response, status
from typing import List, Optional
from ..schemas import ReconRequest, ReconSessionStatus, ReconSessionResults
from ..orchestrator import orchestrator

router = APIRouter()

@router.post("/start")
async def start_recon(request: ReconRequest, response: Response):
    res = await orchestrator.start_session(request)
    if res.get("duplicate_of"):
        response.status_code = status.HTTP_200_OK
    else:
        response.status_code = status.HTTP_202_ACCEPTED
    return res

@router.get("/{session_id}/status", response_model=ReconSessionStatus)
async def get_status(session_id: str):
    if session_id in orchestrator.sessions:
        return orchestrator.sessions[session_id]

    # Fallback to graph_db
    try:
        from ..graph_client import graph_client
        session = await graph_client.get_recon_session(session_id)
        tool_results = session.get("tool_results", {}) or {}
        tool_statuses_raw = tool_results.get("tool_statuses", {}) or {}

        from ..schemas import ToolStatus
        tool_statuses = {k: ToolStatus(v) for k, v in tool_statuses_raw.items()}

        return ReconSessionStatus(
            session_id=session["id"],
            investigation_id=session.get("investigation_id") or session.get("program_id", ""),
            status=session["status"],
            tool_statuses=tool_statuses,
            progress=100.0 if session["status"] != "running" else 0.0
        )
    except Exception as e:
        print(f"Fallback to graph_db failed for session {session_id}: {e}")
        raise HTTPException(status_code=404, detail="Session not found")

@router.get("/sessions", response_model=List[dict])
async def list_sessions(investigation_id: Optional[str] = None, program_id: Optional[str] = None):
    inv_id = investigation_id or program_id
    if not inv_id:
        raise HTTPException(status_code=400, detail="investigation_id or program_id query parameter is required")

    from ..graph_client import graph_client
    try:
        return await graph_client.list_recon_sessions(inv_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch sessions: {e}")

@router.get("/{session_id}/results", response_model=ReconSessionResults)
async def get_results(session_id: str):
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    results = orchestrator.results.get(session_id, None)
    if results is None:
        from ..schemas import ToolResults
        results = ToolResults()

    return ReconSessionResults(session_id=session_id, results=results)

@router.post("/{session_id}/cancel")
async def cancel_recon(session_id: str):
    if session_id not in orchestrator.sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    await orchestrator.cancel_session(session_id)
    return {"status": "cancelled"}
