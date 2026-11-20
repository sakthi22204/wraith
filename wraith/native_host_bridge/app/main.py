from __future__ import annotations

import hmac
import os
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .policy import BUILTIN_ACTIONS, PolicyError, marker_for, validate_job

app = FastAPI(title="Wraith Native Host Bridge")

MAX_BODY_BYTES = 65536


class JobRequest(BaseModel):
    job_id: Any = None
    host_id: Any = None
    token: Any = None
    actions: Any = None
    cleanup: Any = False
    target_url: Any = None
    callback_url: Any = None
    ttl_seconds: Any = None


class AgentError(Exception):
    pass


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


def require_bridge_token(value: str | None) -> None:
    expected = os.getenv("NATIVE_HOST_BRIDGE_TOKEN", "")
    if not expected or not value or not hmac.compare_digest(str(value), expected):
        raise HTTPException(status_code=401, detail="unauthorized")


async def killswitch_active() -> bool:
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        return False
    try:
        import redis.asyncio as redis

        client = redis.from_url(url, socket_timeout=0.3, socket_connect_timeout=0.3)
        try:
            value = await client.get("wraith:killswitch")
        finally:
            await client.aclose()
        if value is None:
            return False
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        return str(value).strip().lower() in {"on", "1", "true"}
    except Exception:
        return True


async def forward_job(agent_url: str, payload: dict) -> dict:
    agent_token = os.getenv("NATIVE_HOST_AGENT_TOKEN") or os.getenv("NATIVE_HOST_BRIDGE_TOKEN", "")
    try:
        timeout = float(os.getenv("NATIVE_HOST_AGENT_TIMEOUT", "2.0"))
    except ValueError:
        timeout = 2.0
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                agent_url.rstrip("/") + "/jobs",
                headers={
                    "X-Wraith-Agent-Token": agent_token,
                    "Content-Type": "application/json",
                },
                json=payload,
            )
    except Exception:
        raise AgentError() from None
    if response.status_code != 200:
        raise AgentError()
    try:
        data = response.json()
    except Exception:
        raise AgentError() from None
    if not isinstance(data, dict):
        raise AgentError()
    return data


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/jobs")
async def create_job(
    request: JobRequest,
    x_wraith_bridge_token: str | None = Header(default=None, alias="X-Wraith-Bridge-Token"),
) -> dict:
    require_bridge_token(x_wraith_bridge_token)
    if await killswitch_active():
        raise HTTPException(status_code=503, detail="killswitch active")
    try:
        job = validate_job(request.model_dump())
    except PolicyError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from None

    payload = {key: job[key] for key in ("job_id", "host_id", "token", "actions", "cleanup", "ttl_seconds")}
    try:
        result = await forward_job(job["agent_url"], payload)
    except AgentError:
        raise HTTPException(status_code=502, detail="host agent request failed") from None

    evidence = result.get("evidence")
    evidence = dict(evidence) if isinstance(evidence, dict) else {}
    cleanup = result.get("cleanup")
    cleanup = dict(cleanup) if isinstance(cleanup, dict) else {}

    marker = marker_for(job["token"], job["job_id"])
    evidence.setdefault("marker", marker)
    evidence.setdefault("probe_marker", marker)
    evidence.setdefault("native_marker", marker)
    for action in BUILTIN_ACTIONS:
        if action in evidence:
            evidence.setdefault(f"{action}_marker", marker)

    return {"evidence": evidence, "cleanup": cleanup, "target_url": job["target_url"]}
