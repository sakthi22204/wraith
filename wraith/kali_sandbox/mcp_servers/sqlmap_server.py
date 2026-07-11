import enum
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import SQLMapResult

class SQLMapMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"

class SQLMapServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("SQLMap Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def run_sqlmap(url: str, param: Optional[str] = None, method: str = "GET", data: Optional[str] = None, caller: Optional[str] = None) -> SQLMapResult:
            """Run SQLMap against a target URL."""
            self.verify_caller("run_sqlmap", caller)
            self.validate_target(url)

            cmd = ["sqlmap", "-u", url, "--batch", "--risk=2", "--level=3"]
            if param:
                cmd.extend(["-p", param])
            if method == SQLMapMethod.POST:
                cmd.extend(["--method", "POST"])
            if data:
                cmd.extend(["--data", data])

            res = await self.run_tool(cmd, timeout=600)

            # Simple heuristic for vulnerability detection from stdout
            vulnerable = "is vulnerable" in res["stdout"] or "Payload:" in res["stdout"]

            return SQLMapResult(
                target=url,
                vulnerable=vulnerable,
                raw_output=res["stdout"] if res["success"] else res.get("error") or res.get("stderr")
            )

if __name__ == "__main__":
    server = SQLMapServer()
    server.mcp.run()
