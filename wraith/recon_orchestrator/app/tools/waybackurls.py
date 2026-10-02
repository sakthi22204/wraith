from typing import List
from .base import ReconTool, host_from_domain, iter_url_lines
from ..schemas import ToolResults, EndpointResult

class WaybackurlsTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="waybackurls", image="waybackurls:latest")

    def get_command(self, domain: str) -> List[str]:
        return [domain]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        # Only lines that are actually URLs; the container's stderr is merged in.
        for url in iter_url_lines(output):
            host = host_from_domain(url) or host_from_domain(domain) or "unknown"
            results.endpoints.append(EndpointResult(host=host, url=url, method="GET", source_tool=self.name))
        return results
