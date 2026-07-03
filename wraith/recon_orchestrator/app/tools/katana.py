import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class KatanaTool(ReconTool):
    def __init__(self):
        super().__init__(name="katana", image="projectdiscovery/katana:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -json output
        return ["-u", domain, "-json", "-silent"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                request = data.get("request", {})
                url = request.get("url")
                method = request.get("method", "GET")
                # host can be extracted from URL if needed
                if url:
                    from urllib.parse import urlparse
                    host = urlparse(url).netloc
                    results.endpoints.append(EndpointResult(
                        host=host,
                        url=url,
                        method=method,
                        source_tool=self.name
                    ))
            except json.JSONDecodeError:
                continue
        return results
