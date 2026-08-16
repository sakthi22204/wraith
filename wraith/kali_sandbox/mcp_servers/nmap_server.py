import enum
import re
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import NmapResult, NmapPort

class NmapScanType(str, enum.Enum):
    SERVICE_DETECTION = "-sV"
    DEFAULT_SCRIPTS = "-sC"
    AGGRESSIVE = "-A"
    FULL_PORT = "-p-"

class NmapServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Nmap Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def run_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV", caller: Optional[str] = None) -> NmapResult:
            """Run an Nmap scan against a target."""
            self.verify_caller("run_nmap_scan", caller)
            self.validate_target(target)

            host, embedded_port = self.split_host_port(target)
            effective_ports = embedded_port or ports
            cmd = ["nmap", scan_type.value if hasattr(scan_type, "value") else scan_type, "-p", effective_ports, host]
            res = await self.run_tool(cmd)

            if not res["success"]:
                return NmapResult(target=target, ports=[], raw_output=res.get("error") or res.get("stderr"))

            return self.parse_nmap_output(target, res["stdout"])

    def parse_nmap_output(self, target: str, stdout: str) -> NmapResult:
        ports = []
        # Simple regex parser for Nmap open ports
        # Example: 80/tcp open  http    Apache httpd 2.4.41
        pattern = re.compile(r"(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s*(.*)")
        for line in stdout.split("\n"):
            match = pattern.search(line)
            if match:
                ports.append(NmapPort(
                    port=int(match.group(1)),
                    protocol=match.group(2),
                    state="open",
                    service=match.group(3),
                    version=match.group(4).strip()
                ))
        return NmapResult(target=target, ports=ports, raw_output=stdout)

if __name__ == "__main__":
    server = NmapServer()
    server.mcp.run()
