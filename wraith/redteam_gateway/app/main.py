"""Redteam C2 gateway.

The only path from an autonomous agent action to BeEF or Empire. It asks the
runner for a scoped, aggressive, rate-limited authorization grant first, then
verifies that grant and the module allowlist before tasking a C2 server.

This service deliberately has no scope database and no killswitch of its own:
those are the runner's authority. Its own controls are inbound authentication,
the C2_AUTONOMY switch, the strict per-server module allowlist, and grant
verification.
"""

import hmac
import os
from typing import Any, Dict, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field

from .adapters import BeefClient, C2Error, EmpireClient
from .grants import authority_of, verify_grant

app = FastAPI(title="Wraith Redteam C2 Gateway")

ADMIN_API_TOKEN = os.getenv("ADMIN_API_TOKEN", "")
RUNNER_URL = os.getenv("RUNNER_URL", "http://active_exploit_runner:8004/api/v1").rstrip("/")
RUNNER_TOKEN = os.getenv("RUNNER_TOKEN", "")
GATE_SECRET = os.getenv("GATE_SECRET", "")
C2_AUTONOMY = os.getenv("C2_AUTONOMY", "off").strip().lower()
REQUEST_TIMEOUT_SECONDS = float(os.getenv("C2_REQUEST_TIMEOUT_SECONDS", "60"))
BEEF_PUBLIC_URL = os.getenv("BEEF_PUBLIC_URL", "http://127.0.0.1:3001")

# Keys are matched against the class/name exposed by the pinned BeEF image.
# `browser_details` was an older alias that image does not ship; the
# fingerprinting module is the read-only replacement.
DEFAULT_BEEF_MODULES = {
    "fingerprint_browser",
    "get_visited_urls",
    "get_page_html",
    "get_geolocation",
    "detect_social_networks",
}
DEFAULT_EMPIRE_MODULES = {
    "powershell/situational_awareness/host/win32processes",
    "powershell/situational_awareness/host/getav",
    "powershell/situational_awareness/network/nslookup",
}


def _module_allowlist(name: str, defaults: set) -> set:
    raw = os.getenv(name, "").strip()
    if not raw:
        return set(defaults)
    return {item.strip() for item in raw.split(",") if item.strip()}


BEEF_MODULES = _module_allowlist("BEEF_MODULE_ALLOWLIST", DEFAULT_BEEF_MODULES)
EMPIRE_MODULES = _module_allowlist("EMPIRE_MODULE_ALLOWLIST", DEFAULT_EMPIRE_MODULES)


def _matches(presented: str | None, expected: str) -> bool:
    if not presented or not expected:
        return False
    return hmac.compare_digest(presented.encode(), f"Bearer {expected}".encode())


async def require_admin_token(authorization: Optional[str] = Header(None)) -> str:
    if not _matches(authorization, ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "admin"


class C2Action(BaseModel):
    investigation_id: str = Field(..., validation_alias="investigation_id")
    action: str
    target: str
    c2_target: str = ""
    module: str = ""
    options: Dict[str, Any] = Field(default_factory=dict)
    actor_note: str = ""


def _check_module(action: str, module: str) -> None:
    if action == "beef_command":
        if module not in BEEF_MODULES:
            raise HTTPException(status_code=403, detail=f"BeEF module {module!r} is not in the allowlist")
    elif action == "empire_task":
        if module not in EMPIRE_MODULES:
            raise HTTPException(status_code=403, detail=f"Empire module {module!r} is not in the allowlist")
    elif action != "beef_hook":
        raise HTTPException(status_code=400, detail=f"Unsupported C2 action {action!r}")


async def _authorize(payload: dict, actor_note: str) -> dict:
    headers = {"Authorization": f"Bearer {RUNNER_TOKEN}"}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_SECONDS) as client:
        try:
            response = await client.post(
                f"{RUNNER_URL}/redteam/authorize", json=payload, headers=headers,
            )
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"Runner authorization failed: {exc}") from exc
    if response.status_code >= 400:
        detail = response.text[:1000]
        raise HTTPException(status_code=response.status_code, detail=f"Runner refused C2 authorization: {detail}")
    return response.json()


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "autonomy": C2_AUTONOMY}


@app.post("/api/v1/c2/actions")
async def run_c2_action(
    request: C2Action,
    _auth: str = Depends(require_admin_token),
) -> dict:
    if C2_AUTONOMY != "full":
        raise HTTPException(status_code=403, detail="C2 autonomy is disabled; set C2_AUTONOMY=full to task C2")
    if not GATE_SECRET:
        raise HTTPException(status_code=500, detail="GATE_SECRET is not configured")

    action = (request.action or "").strip()
    module = (request.module or "").strip()
    _check_module(action, module)

    auth_payload = {
        "investigation_id": request.investigation_id,
        "action": action,
        "target": request.target,
        "c2_target": request.c2_target,
        "module": module,
        "options": request.options,
        "actor_note": request.actor_note,
    }
    authorized = await _authorize(auth_payload, request.actor_note)
    grant = authorized.get("grant")
    try:
        claims = verify_grant(grant, GATE_SECRET)
    except ValueError as exc:
        raise HTTPException(status_code=403, detail=f"Runner grant rejected: {exc}") from exc

    expected_host = authority_of(request.target)
    if (
        claims.get("caller") != "redteam_gateway"
        or claims.get("inv") != request.investigation_id
        or claims.get("host") != expected_host
        or action not in (claims.get("tools") or [])
    ):
        raise HTTPException(status_code=403, detail="Runner grant does not match this C2 request")

    try:
        if action == "beef_hook":
            hook_url = BEEF_PUBLIC_URL
            result = {
                "hook_url": f"{hook_url.rstrip('/')}/hook.js",
                "instruction": "Deliver the hook script only to the authorized target.",
            }
        elif action == "beef_command":
            result = await BeefClient().execute(request.c2_target, module, request.options)
        else:
            result = await EmpireClient().execute(request.c2_target, module, request.options)
    except C2Error as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "status": "completed",
        "action": action,
        "target": authorized.get("target", request.target),
        "c2_target": request.c2_target,
        "module": module,
        "result": result,
    }
