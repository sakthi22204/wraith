import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, HostResult

class SubfinderTool(ReconTool):
    def __init__(self):
        super().__init__(name="subfinder", image="projectdiscovery/subfinder:latest")

    def get_command(self, domain: str) -> List[str]:
        # -d domain, -json output
        return ["-d", domain, "-json"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host")
                if host:
                    results.hosts.append(HostResult(value=host, source_tool=self.name))
            except json.JSONDecodeError:
                continue
        return results
