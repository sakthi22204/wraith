import re
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import HydraResult

class HydraServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Hydra Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def run_hydra(target: str, service: str, user: str, pass_list: str, caller: Optional[str] = None) -> HydraResult:
            """
            Run Hydra brute-force against a target.
            pass_list should be a path to a small wordlist bundled in the container.
            """
            self.verify_caller("run_hydra", caller)
            self.validate_target(target)
            self.validate_target(service) # Validate service as well

            # Use bundled wordlists only for safety in this phase
            if not pass_list.startswith("/app/wordlists/"):
                raise ValueError("Only bundled wordlists in /app/wordlists/ are allowed.")

            # Hard cap on attempts/concurrency for safety
            cmd = ["hydra", "-l", user, "-P", pass_list, "-f", "-t", "4", target, service]
            res = await self.run_tool(cmd, timeout=300)

            valid_creds = []
            # Parse output for successful logins
            # Example: [80][http-get] host: 127.0.0.1   login: admin   password: password
            pattern = re.compile(r"login: ([^\s]+)\s+password: ([^\s]+)")
            for line in res["stdout"].split("\n"):
                match = pattern.search(line)
                if match:
                    valid_creds.append({"user": match.group(1), "password": match.group(2)})

            return HydraResult(
                target=target,
                service=service,
                valid_credentials=valid_creds,
                raw_output=res["stdout"]
            )

if __name__ == "__main__":
    server = HydraServer()
    server.mcp.run()
