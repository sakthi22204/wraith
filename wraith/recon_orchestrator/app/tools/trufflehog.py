import re
from typing import List
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

class TrufflehogTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="trufflehog", image="trufflesecurity/trufflehog:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["git", f"http://{domain}"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if "leak" in line.lower() or "secret" in line.lower() or "found" in line.lower():
                url = absolute_url("/trufflehog-finding", domain)
                results.endpoints.append(EndpointResult(host=host_from_domain(url) or host_from_domain(domain) or "unknown", url=url, method="GET", source_tool=self.name))
        return results
