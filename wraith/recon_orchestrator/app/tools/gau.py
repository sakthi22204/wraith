from typing import List
from .base import ReconTool, host_from_domain, iter_url_lines
from ..schemas import ToolResults, EndpointResult

class GauTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 900
    def __init__(self):
        super().__init__(name="gau", image="gau:latest")

    def get_command(self, domain: str) -> List[str]:
        return [domain]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        # Only lines that are actually URLs: gau's config warnings arrive on the
        # same stream and are not endpoints.
        for url in iter_url_lines(output):
            # gau reports whole URLs; keeping them intact is what makes the
            # endpoint attributable to a host downstream.
            host = host_from_domain(url) or host_from_domain(domain) or "unknown"
            results.endpoints.append(EndpointResult(host=host, url=url, method="GET", source_tool=self.name))
        return results
