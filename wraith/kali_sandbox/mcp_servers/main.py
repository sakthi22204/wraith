import os
import json
from contextvars import ContextVar
from typing import Optional
from mcp.server.fastmcp import FastMCP
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from .nmap_server import NmapServer
from .nuclei_server import NucleiServer
from .sqlmap_server import SQLMapServer
from .hydra_server import HydraServer
from .metasploit_server import MetasploitServer

# Create a single MCP server instance
mcp = FastMCP("Wraith Security Tools", host="0.0.0.0", port=8000)

caller_context: ContextVar[Optional[str]] = ContextVar("caller_context", default=None)

DANGEROUS_TOOLS = {"run_hydra", "run_msf_module"}
AUTHORIZED_DANGEROUS_CALLERS = set(os.getenv("AUTHORIZED_DANGEROUS_CALLERS", "active_exploit_runner").split(","))

def verify_caller(tool_name: str, caller: Optional[str]):
    if tool_name not in DANGEROUS_TOOLS:
        return

    if caller not in AUTHORIZED_DANGEROUS_CALLERS:
        raise HTTPException(status_code=403, detail=f"Caller {caller} is not authorized to use {tool_name}")

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

# Initialize tool providers
nmap = NmapServer()
nuclei = NucleiServer()
sqlmap = SQLMapServer()
hydra = HydraServer()
metasploit = MetasploitServer()

# Register tools from each provider to the main mcp instance
@mcp.tool()
async def run_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV"):
    caller = get_caller()
    return await nmap.mcp.call_tool("run_nmap_scan", {"target": target, "ports": ports, "scan_type": scan_type, "caller": caller})

@mcp.tool()
async def run_nuclei_scan(target: str, category: str = "default"):
    caller = get_caller()
    return await nuclei.mcp.call_tool("run_nuclei_scan", {"target": target, "category": category, "caller": caller})

@mcp.tool()
async def run_sqlmap(url: str, param: str = None, method: str = "GET", data: str = None):
    caller = get_caller()
    return await sqlmap.mcp.call_tool("run_sqlmap", {"url": url, "param": param, "method": method, "data": data, "caller": caller})

@mcp.tool()
async def run_hydra(target: str, service: str, user: str, pass_list: str):
    caller = get_caller()
    verify_caller("run_hydra", caller)
    return await hydra.mcp.call_tool("run_hydra", {"target": target, "service": service, "user": user, "pass_list": pass_list, "caller": caller})

@mcp.tool()
async def list_msf_modules(search: str):
    caller = get_caller()
    return await metasploit.mcp.call_tool("list_modules", {"search": search, "caller": caller})

@mcp.tool()
async def run_msf_module(module: str, target: str, options: dict):
    caller = get_caller()
    verify_caller("run_msf_module", caller)
    return await metasploit.mcp.call_tool("run_module", {"module": module, "target": target, "options": options, "caller": caller})

# Add internal REST bridge for Phase 5 executor
@mcp.custom_route("/tools/{tool_name}/call", methods=["POST"])
async def call_tool_internal(request):
    # FastMCP custom_route passes the Starlette request object
    body = await request.json()
    tool_name = request.path_params["tool_name"]

    caller = request.headers.get("X-Wraith-Caller")
    verify_caller(tool_name, caller)

    # Set context for the duration of this call so @mcp.tool() wrappers can see it
    token = caller_context.set(caller)

    # FastMCP stores tool handlers in a dictionary
    # For simplicity, we just use call_tool which is an internal method
    # It returns [TextContent, ...]
    try:
        result = await mcp.call_tool(tool_name, body)
    except Exception as e:
        # Convert internal tool errors to JSON results
        return JSONResponse(content={"error": str(e), "success": False}, status_code=500)
    finally:
        caller_context.reset(token)

    # Since call_tool returns a list of Content objects, we need to serialize them
    return JSONResponse(content=jsonable_encoder(result))

# Lightweight health check endpoint for Docker healthcheck (avoids relying
# on the SSE stream endpoint, which never "completes" a normal HTTP request)
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse(content={"status": "healthy"})

if __name__ == "__main__":
    mcp.run(transport="sse")
