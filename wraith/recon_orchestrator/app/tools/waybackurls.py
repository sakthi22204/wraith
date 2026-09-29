from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class WaybackurlsTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="waybackurls", image="waybackurls:latest")

    def get_command(self, domain: str) -> List[str]:
        return [domain]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            url = line.strip()
            if url:
                host = "unknown"
                path = "/"
                if "://" in url:
                    parts = url.split("://")[1].split("/", 1)
                    host = parts[0]
                    path = "/" + parts[1] if len(parts) > 1 else "/"
                results.endpoints.append(EndpointResult(host=host, url=path, method="GET", source_tool=self.name))
        return results
