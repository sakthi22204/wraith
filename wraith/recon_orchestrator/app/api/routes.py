from fastapi import APIRouter, HTTPException
from typing import List
from ..schemas import ReconRequest, ReconSessionStatus, ReconSessionResults
from ..orchestrator import orchestrator

router = APIRouter()

@router.post("/start", status_code=202)
async def start_recon(request: ReconRequest):
    session_id = await orchestrator.start_session(request)
    return {"session_id": session_id}

@router.get("/{session_id}/status", response_model=ReconSessionStatus)
async def get_status(session_id: str):
    if session_id in orchestrator.sessions:
        return orchestrator.sessions[session_id]

    # Fallback to graph_db
    try:
        from ..graph_client import graph_client
        session = await graph_client.get_recon_session(session_id)
        # Convert ReconSession from graph to ReconSessionStatus
        # Some fields like progress or detailed tool_statuses might be lost/summarized
        # if not stored in tool_results.
        tool_results = session.get("tool_results", {})
        tool_statuses_raw = tool_results.get("tool_statuses", {})

        # ReconSessionStatus expects ToolStatus enum values
        from ..schemas import ToolStatus
        tool_statuses = {k: ToolStatus(v) for k, v in tool_statuses_raw.items()}

        return ReconSessionStatus(
            session_id=session["id"],
            program_id=session["program_id"],
            status=session["status"],
            tool_statuses=tool_statuses,
            progress=100.0 if session["status"] != "running" else 0.0 # simplified
        )
    except Exception as e:
        print(f"Fallback to graph_db failed for session {session_id}: {e}")
        raise HTTPException(status_code=404, detail="Session not found")

@router.get("/sessions", response_model=List[dict])
async def list_sessions(program_id: str):
    from ..graph_client import graph_client
    try:
        return await graph_client.list_recon_sessions(program_id)
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
