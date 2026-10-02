import json
from typing import List
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

class KiterunnerTool(ReconTool):
    def __init__(self):
        super().__init__(name="kiterunner", image="kiterunner:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["kb", "scan", f"http://{domain}/api", "-w", "/wordlists/routes-small.kite", "-o", "json"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                path = data.get("path") or data.get("url")
                if path:
                    # kiterunner reports a path relative to its own scan root, so
                    # the target has to be re-attached here.
                    url = absolute_url(path, domain)
                    host = host_from_domain(url) or host_from_domain(domain) or "unknown"
                    results.endpoints.append(EndpointResult(host=host, url=url, method=data.get("method", "GET"), source_tool=self.name))
            except json.JSONDecodeError:
                continue
        return results
