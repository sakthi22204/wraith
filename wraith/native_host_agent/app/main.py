from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .driver import DriverError, execute

app = FastAPI(title="Wraith Native Host Agent")

MAX_BODY_BYTES = 65536


class AgentJobRequest(BaseModel):
    job_id: Any = None
    host_id: Any = None
    token: Any = None
    actions: Any = None
    cleanup: Any = False
    target_url: Any = None
    callback_url: Any = None
    ttl_seconds: Any = None


@app.middleware("http")
async def body_limit(request: Request, call_next):
    length = request.headers.get("content-length")
    if length:
        try:
            size = int(length)
        except ValueError:
            size = 0
        if size > MAX_BODY_BYTES:
            return JSONResponse(status_code=413, content={"detail": "payload too large"})
    return await call_next(request)


def require_agent_token(value: str | None) -> None:
    expected = os.getenv("NATIVE_HOST_AGENT_TOKEN", "")
    if not expected or not value or not hmac.compare_digest(str(value), expected):
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/jobs")
async def run_job(
    request: AgentJobRequest,
    x_wraith_agent_token: str | None = Header(default=None, alias="X-Wraith-Agent-Token"),
) -> dict:
    require_agent_token(x_wraith_agent_token)
    try:
        return execute(request.model_dump())
    except DriverError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None
    except Exception:
        raise HTTPException(status_code=500, detail="probe execution failed") from None
