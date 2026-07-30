import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, HostResult

class DnsxTool(ReconTool):
    def __init__(self):
        super().__init__(name="dnsx", image="projectdiscovery/dnsx:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-d", domain, "-resp-only", "-json"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host") or data.get("name")
                if host:
                    results.hosts.append(HostResult(value=host, source_tool=self.name))
            except json.JSONDecodeError:
                continue
        return results
