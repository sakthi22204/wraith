import re
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, PortResult

class NmapTool(ReconTool):
    def __init__(self):
        super().__init__(name="nmap", image="instrumentisto/nmap:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-T4", "-F", domain]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        # Parse standard nmap output
        # e.g., '80/tcp open http'
        for line in output.strip().split("\n"):
            match = re.search(r'(\d+)/(tcp|udp)\s+open\s+([a-zA-Z0-9\.-]+)', line)
            if match:
                port_num = int(match.group(1))
                proto = match.group(2)
                state = "open"
                results.ports.append(PortResult(host="unknown", number=port_num, protocol=proto, state=state, source_tool=self.name))
        return results
