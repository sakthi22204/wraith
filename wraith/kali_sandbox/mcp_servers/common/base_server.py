import asyncio
import re
import subprocess
from typing import List, Optional
from mcp.server.fastmcp import FastMCP

class BaseSecurityServer:
    def __init__(self, name: str):
        self.mcp = FastMCP(name)
        self.dangerous_tools = {"run_msf_module", "run_hydra"}
        self.authorized_callers = set(os.getenv("AUTHORIZED_DANGEROUS_CALLERS", "active_exploit_runner").split(","))
        # Basic validation: alphanumeric, dots, hyphens, colons (for ports/URLs)
        # No shell metacharacters like ; | & > < $ ( )
        self.target_regex = re.compile(r"^[a-zA-Z0-9\.\-\_\:\/]+$")

    def validate_target(self, target: str):
        if not self.target_regex.fullmatch(target):
            raise ValueError(f"Invalid target: {target}. Potential command injection detected.")

    def verify_caller(self, tool_name: str, caller: Optional[str]):
        if tool_name not in self.dangerous_tools:
            return
        if caller not in self.authorized_callers:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail=f"Caller {caller} is not authorized to use {tool_name}")

    async def run_tool(self, cmd: List[str], timeout: int = 300) -> dict:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                return {
                    "stdout": stdout.decode(),
                    "stderr": stderr.decode(),
                    "exit_code": process.returncode,
                    "success": process.returncode == 0
                }
            except asyncio.TimeoutError:
                process.kill()
                return {
                    "error": "Tool timed out",
                    "exit_code": -1,
                    "success": False
                }
        except Exception as e:
            return {
                "error": str(e),
                "exit_code": -1,
                "success": False
            }
