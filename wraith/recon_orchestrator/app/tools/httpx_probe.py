import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class HttpxProbeTool(ReconTool):
    def __init__(self):
        # Using official image. Note: projectdiscovery/httpx
        super().__init__(name="httpx", image="projectdiscovery/httpx:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -json output, -silent
        return ["-u", domain, "-json", "-silent"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url")
                host = data.get("host")
                method = data.get("method", "GET")
                if url:
                    results.endpoints.append(EndpointResult(
                        host=host or domain, # Fallback if host missing
                        url=url,
                        method=method,
                        source_tool=self.name
                    ))
            except json.JSONDecodeError:
                continue
        return results
