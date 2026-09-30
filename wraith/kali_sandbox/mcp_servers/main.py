import os
import json
from contextvars import ContextVar
from typing import Optional, List
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from .nmap_server import NmapServer
from .nuclei_server import NucleiServer
from .sqlmap_server import SQLMapServer
from .hydra_server import HydraServer
from .metasploit_server import MetasploitServer
from .http_probe_server import HttpProbeServer
from .gate import GateError, enforce

# Create a single MCP server instance
mcp = FastMCP("Wraith Security Tools", host="0.0.0.0", port=8000)

caller_context: ContextVar[Optional[str]] = ContextVar("caller_context", default=None)

DANGEROUS_TOOLS = {"run_hydra", "run_msf_module"}

# Tools that send traffic to a caller-supplied destination. Each is gated on
# killswitch + signed grant + re-read scope, not merely on who the caller says
# it is: the request body chooses the destination, so a caller name proves
# nothing about where the packet is going.
GATED_NETWORK_TOOLS = {
    "http_probe", "http_probe_diff", "http_probe_race", "http_probe_threshold",
}
AUTHORIZED_DANGEROUS_CALLERS = set(os.getenv("AUTHORIZED_DANGEROUS_CALLERS", "active_exploit_runner").split(","))

def verify_caller(tool_name: str, caller: Optional[str]):
    if tool_name not in DANGEROUS_TOOLS:
        return

    if caller not in AUTHORIZED_DANGEROUS_CALLERS:
        raise HTTPException(status_code=403, detail=f"Caller {caller} is not authorized to use {tool_name}")

grant_context: ContextVar[Optional[str]] = ContextVar("grant_context", default=None)


def gate_request(tool_name: str, body: dict, request=None):
    """Enforce killswitch, grant and scope before a gated tool sends anything."""
    if tool_name not in GATED_NETWORK_TOOLS:
        return
    from .config import settings
    caller = (request.headers.get("X-Wraith-Caller") if request is not None else None) or get_caller()
    grant_token = (request.headers.get("X-Wraith-Grant") if request is not None else None) or grant_context.get()
    targets = [str(body.get("url") or "")]
    for variant in body.get("variants") or []:
        if isinstance(variant, dict) and variant.get("url"):
            targets.append(str(variant["url"]))
    try:
        enforce(caller=caller, grant_token=grant_token,
                targets=[t for t in targets if t], settings=settings)
    except GateError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)


# Prefixes a probe tool raises for a request it refuses to send. These are
# argument errors, not sandbox failures: an unknown identity or an out-of-range
# count means the caller must fix the request, and reporting it as a 500 would
# read as an outage and invite pointless retries.
_REJECTED_ARGUMENT_PREFIXES = (
    "unknown identity",
    "unknown baseline identity",
    "duplicate identity label",
    "identity labels must be",
    "at least one variant",
    "at most",
    "count must be",
    "at least 2",
    "interval must be",
    "variants per comparison",
    "comparison exceeds",
    "insufficient",
    "exceeds the permitted",
    "unsupported method",
    "scheme",
    "no host",
    "invalid url",
)


def _is_rejected_argument(detail: str) -> bool:
    """True when a tool's error means 'this request was refused', not 'it broke'.

    FastMCP prefixes the tool's own message with "Error executing tool <name>:",
    so a prefix match against the raw string would miss every case.
    """
    text = (detail or "").lower()
    message = text
    # The prefix is added once per MCP hop, so an outer tool re-reporting an
    # inner tool's error stacks it. Strip every layer before matching.
    while True:
        _, marker, after = message.partition("error executing tool")
        if not marker:
            break
        _, _, after = after.partition(":")
        message = after.strip()
    return any(message.startswith(p) for p in _REJECTED_ARGUMENT_PREFIXES)


def get_caller() -> Optional[str]:
    try:
        ctx = mcp.get_context()
        if ctx and ctx._request_context:
            request = ctx.request_context.request
            if request and hasattr(request, "headers"):
                val = request.headers.get("X-Wraith-Caller")
                if val:
                    return val
    except Exception:
        pass
    return caller_context.get()

def unwrap_inner(result):
    """The per-tool servers' call_tool returns a (content_blocks, structured)
    tuple. Returning that tuple from an outer @mcp.tool() makes FastMCP encode
    it twice, so the agent sees duplicated JSON. Return just the structured
    payload so it is serialized exactly once (JSON blocks), never the tuple."""
    if isinstance(result, tuple) and len(result) == 2:
        structured = result[1]
        if isinstance(structured, (dict, list, BaseModel)):
            return structured
        return result[0]
    return result

# Initialize tool providers
nmap = NmapServer()
nuclei = NucleiServer()
sqlmap = SQLMapServer()
hydra = HydraServer()
metasploit = MetasploitServer()
http_probe_server = HttpProbeServer()

# Register tools from each provider to the main mcp instance
@mcp.tool()
async def run_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV"):
    caller = get_caller()
    return unwrap_inner(await nmap.mcp.call_tool("run_nmap_scan", {"target": target, "ports": ports, "scan_type": scan_type, "caller": caller}))

@mcp.tool()
async def run_nuclei_scan(target: str, category: str = "default"):
    caller = get_caller()
    return unwrap_inner(await nuclei.mcp.call_tool("run_nuclei_scan", {"target": target, "category": category, "caller": caller}))

@mcp.tool()
async def run_sqlmap(url: str, param: str = None, method: str = "GET", data: str = None):
    caller = get_caller()
    return unwrap_inner(await sqlmap.mcp.call_tool("run_sqlmap", {"url": url, "param": param, "method": method, "data": data, "caller": caller}))

@mcp.tool()
async def run_hydra(target: str, service: str, user: str, pass_list: str):
    caller = get_caller()
    verify_caller("run_hydra", caller)
    return unwrap_inner(await hydra.mcp.call_tool("run_hydra", {"target": target, "service": service, "user": user, "pass_list": pass_list, "caller": caller}))

@mcp.tool()
async def list_msf_modules(search: str):
    caller = get_caller()
    return unwrap_inner(await metasploit.mcp.call_tool("list_modules", {"search": search, "caller": caller}))

@mcp.tool()
async def run_msf_module(module: str, target: str, options: dict):
    caller = get_caller()
    verify_caller("run_msf_module", caller)
    return unwrap_inner(await metasploit.mcp.call_tool("run_module", {"module": module, "target": target, "options": options, "caller": caller}))

@mcp.tool()
async def http_probe(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
):
    """Send one agent-authored HTTP request and capture the full raw response.

    This is the validation primitive: craft the exact request a hypothesis
    predicts, execute it, and inspect what actually came back. Safety gates
    (scope, killswitch, rate limit) are enforced by the caller in
    active_exploit_runner before this tool is ever reached.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects, "caller": caller,
    }))

@mcp.tool()
async def http_probe_diff(
    url: str,
    variants: List[dict],
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    identities: Optional[List[dict]] = None,
    baseline_identity: Optional[str] = None,
):
    """Send a request, re-send it with deliberate changes, and diff the responses.

    This is how bugs that only exist as a *difference* get evidence: broken
    object-level authorization, input handling, error-based disclosure. Each
    variant must target the same host/port/scheme as the baseline, and a
    difference is only material if it survives normalization of expected
    volatile fields.

    Pass test accounts as named `identities` and reference them by label from a
    variant to compare what two principals can see. Credential values are used
    to send the request and then withheld from the returned evidence. Use only
    accounts you own or are authorized to test with. Safety gates (scope,
    killswitch, rate limit) are enforced by active_exploit_runner before this
    tool is reached.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_diff", {
        "url": url, "variants": variants, "method": method, "headers": headers,
        "body": body, "timeout": timeout, "follow_redirects": follow_redirects,
        "identities": identities, "baseline_identity": baseline_identity,
        "caller": caller,
    }))

@mcp.tool()
async def http_probe_race(
    url: str,
    method: str = "POST",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    count: int = 3,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Send one request several times concurrently and return every capture.

    For single-use actions (coupon redemption, account creation, checkout, vote)
    the observable question is whether the endpoint serializes the operation:
    if more than one of several simultaneous identical requests succeeds, the
    action is not serialized. The concurrent count is small and bounded on
    purpose — this is a missing-lock check, not a stress tool. Safety gates
    (scope, killswitch, rate limit) are enforced by active_exploit_runner before
    this tool is reached.

    Declare ``identities`` and name one in ``identity`` to run the whole burst as
    a single authenticated user, which is the meaningful test for a one-shot
    capability. The session token is withheld from the returned evidence.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_race", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects,
        "count": count, "identities": identities, "identity": identity,
        "caller": caller,
    }))

@mcp.tool()
async def http_probe_threshold(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    count: int = 10,
    interval: float = 0.25,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Send one request repeatedly in sequence to observe where throttling starts.

    For a missing rate limit on login, password reset or any expensive endpoint.
    Absence of a limit is only observable by exceeding one, so this repeats the
    request and reports the index of the first refusal; a zero means no throttle
    was seen within the tested range. Requests are sequential deliberately — a
    rate limiter counts arrivals over a window, so a burst would measure
    concurrency instead. Count is bounded; this measures a budget rather than
    loading a host. Safety gates are enforced by active_exploit_runner first.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_threshold", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects,
        "count": count, "interval": interval,
        "identities": identities, "identity": identity, "caller": caller,
    }))

# Add internal REST bridge for Phase 5 executor
@mcp.custom_route("/tools/{tool_name}/call", methods=["POST"])
async def call_tool_internal(request):
    # FastMCP custom_route passes the Starlette request object
    body = await request.json()
    tool_name = request.path_params["tool_name"]

    caller = request.headers.get("X-Wraith-Caller")
    verify_caller(tool_name, caller)

    # Set context for the duration of this call so @mcp.tool() wrappers can see it
    try:
        gate_request(tool_name, body, request=request)
    except HTTPException as exc:
        return JSONResponse(content={"error": exc.detail, "success": False},
                            status_code=exc.status_code)

    token = caller_context.set(caller)
    grant_token = grant_context.set(request.headers.get("X-Wraith-Grant"))

    # FastMCP stores tool handlers in a dictionary
    # For simplicity, we just use call_tool which is an internal method
    # It returns [TextContent, ...]
    try:
        result = await mcp.call_tool(tool_name, body)
    except Exception as e:
        # A rejected argument (unknown identity, count out of range) is the
        # caller's mistake, not a sandbox failure, so it is reported as a 400
        # with the reason rather than a 500. FastMCP wraps a tool's own
        # exception in ToolError, so the rejected-argument signal has to be
        # recovered from the message.
        detail = str(e)
        if _is_rejected_argument(detail):
            return JSONResponse(content={"error": detail, "success": False},
                                status_code=400)
        return JSONResponse(content={"error": detail, "success": False}, status_code=500)
    finally:
        caller_context.reset(token)
        grant_context.reset(grant_token)

    # Since call_tool returns a list of Content objects, we need to serialize them
    return JSONResponse(content=jsonable_encoder(result))

# Lightweight health check endpoint for Docker healthcheck (avoids relying
# on the SSE stream endpoint, which never "completes" a normal HTTP request)
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse(content={"status": "healthy"})

if __name__ == "__main__":
    mcp.run(transport="sse")
