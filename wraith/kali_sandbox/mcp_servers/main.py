from mcp.server.fastmcp import FastMCP
from .nmap_server import NmapServer
from .nuclei_server import NucleiServer
from .sqlmap_server import SQLMapServer
from .hydra_server import HydraServer
from .metasploit_server import MetasploitServer

# Create a single MCP server instance
mcp = FastMCP("Wraith Security Tools", host="0.0.0.0", port=8000)

# Initialize tool providers
nmap = NmapServer()
nuclei = NucleiServer()
sqlmap = SQLMapServer()
hydra = HydraServer()
metasploit = MetasploitServer()

# Register tools from each provider to the main mcp instance
# We need to wrap them or just use the tool decorators directly if we refactored.
# For now, let's just use the ones we already defined by accessing their tool functions.

@mcp.tool()
async def run_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV"):
    return await nmap.mcp.call_tool("run_nmap_scan", {"target": target, "ports": ports, "scan_type": scan_type})

@mcp.tool()
async def run_nuclei_scan(target: str, category: str = "default"):
    return await nuclei.mcp.call_tool("run_nuclei_scan", {"target": target, "category": category})

@mcp.tool()
async def run_sqlmap(url: str, param: str = None, method: str = "GET", data: str = None):
    return await sqlmap.mcp.call_tool("run_sqlmap", {"url": url, "param": param, "method": method, "data": data})

@mcp.tool()
async def run_hydra(target: str, service: str, user: str, pass_list: str):
    return await hydra.mcp.call_tool("run_hydra", {"target": target, "service": service, "user": user, "pass_list": pass_list})

@mcp.tool()
async def list_msf_modules(search: str):
    return await metasploit.mcp.call_tool("list_modules", {"search": search})

@mcp.tool()
async def run_msf_module(module: str, target: str, options: dict):
    return await metasploit.mcp.call_tool("run_module", {"module": module, "target": target, "options": options})

if __name__ == "__main__":
    mcp.run(transport="sse")
