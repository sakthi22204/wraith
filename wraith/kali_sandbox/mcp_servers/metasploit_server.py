import re
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import MetasploitResult, MetasploitModule

class MetasploitServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Metasploit Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def list_modules(search: str) -> List[MetasploitModule]:
            """Search for Metasploit modules."""
            self.validate_target(search) # Reuse validation to prevent injection
            # Use msfconsole -x to run search command
            cmd = ["msfconsole", "-q", "-x", f"search {search}; exit"]
            res = await self.run_tool(cmd, timeout=60)

            modules = []
            # Parse table output from msfconsole search
            # #  Name                                           Disclosure Date  Rank    Check  Description
            # -  ----                                           ---------------  ----    -----  -----------
            # 0  exploit/multi/http/juice_shop_sqli             2021-01-01       excellent  Yes    OWASP Juice Shop SQLi

            pattern = re.compile(r"^\s*\d+\s+([^\s]+)\s+\d{4}-\d{2}-\d{2}\s+([^\s]+)\s+(Yes|No)\s+(.*)")
            for line in res["stdout"].split("\n"):
                match = pattern.match(line)
                if match:
                    modules.append(MetasploitModule(
                        fullname=match.group(1),
                        name=match.group(1).split("/")[-1],
                        type=match.group(1).split("/")[0],
                        rank=match.group(2),
                        description=match.group(4).strip()
                    ))
            return modules

        @self.mcp.tool()
        async def run_module(module: str, target: str, options: dict) -> MetasploitResult:
            """Run a Metasploit module against a target."""
            self.validate_target(target)
            self.validate_target(module)

            # Basic validation for options
            sanitized_opts = []
            for k, v in options.items():
                if self.target_regex.match(str(k)) and self.target_regex.match(str(v)):
                    sanitized_opts.append(f"set {k} {v}")

            opts_str = " ".join(sanitized_opts)
            cmd_str = f"use {module}; set RHOSTS {target}; {opts_str}; run; exit"
            cmd = ["msfconsole", "-q", "-x", cmd_str]

            res = await self.run_tool(cmd, timeout=600)

            success = "Session" in res["stdout"] or "Exploit completed" in res["stdout"]
            session_info = {}
            if "opened" in res["stdout"]:
                # Try to extract session ID
                match = re.search(r"Session (\d+) opened", res["stdout"])
                if match:
                    session_info["session_id"] = match.group(1)

            return MetasploitResult(
                module=module,
                success=success,
                session_info=session_info,
                raw_output=res["stdout"]
            )

if __name__ == "__main__":
    server = MetasploitServer()
    server.mcp.run()
