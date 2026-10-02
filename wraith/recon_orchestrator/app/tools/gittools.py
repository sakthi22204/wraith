from typing import List
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

class GittoolsTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="gittools", image="gittools:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-u", f"http://{domain}"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        out_lower = output.lower()
        if "no exposed" in out_lower or "not found" in out_lower or "no git" in out_lower:
            return results
        if "found" in out_lower or "exposed" in out_lower or "git" in out_lower:
            if "usage:" in out_lower or "error" in out_lower:
                return results
            url = absolute_url("/.git/", domain)
            results.endpoints.append(EndpointResult(host=host_from_domain(url) or host_from_domain(domain) or "unknown", url=url, method="GET", source_tool=self.name))
        return results
