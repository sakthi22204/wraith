import asyncio
import re
import subprocess
from typing import List, Optional
from mcp.server.fastmcp import FastMCP

class BaseSecurityServer:
    def __init__(self, name: str):
        self.mcp = FastMCP(name)
        # Basic validation: alphanumeric, dots, hyphens, colons (for ports/URLs)
        # No shell metacharacters like ; | & > < $ ( )
        self.target_regex = re.compile(r"^[a-zA-Z0-9\.\-\_\:\/]+$")

    def validate_target(self, target: str):
        if not self.target_regex.match(target):
            raise ValueError(f"Invalid target: {target}. Potential command injection detected.")

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
