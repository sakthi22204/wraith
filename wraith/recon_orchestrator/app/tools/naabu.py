import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, PortResult

class NaabuTool(ReconTool):
    def __init__(self):
        super().__init__(name="naabu", image="projectdiscovery/naabu:latest")

    def get_command(self, domain: str) -> List[str]:
        # -host domain, -json output
        return ["-host", domain, "-json", "-silent"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        seen_ports = set()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host")
                port = data.get("port")
                if host and port:
                    port_key = (host.lower(), int(port))
                    if port_key in seen_ports:
                        continue
                    seen_ports.add(port_key)
                    results.ports.append(PortResult(
                        host=host,
                        number=int(port),
                        protocol="tcp", # Naabu defaults to TCP
                        state="open",
                        source_tool=self.name
                    ))
            except json.JSONDecodeError:
                continue
        return results
