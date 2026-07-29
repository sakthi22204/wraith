import re
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class LinkfinderTool(ReconTool):
    def __init__(self):
        super().__init__(name="linkfinder", image="linkfinder:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-i", f"http://{domain}", "-o", "cli"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            url = line.strip()
            if url:
                match = re.search(r'(?:https?://[a-zA-Z0-9\.-]+)?(/[a-zA-Z0-9\.-_/]+)', url)
                if match:
                    results.endpoints.append(EndpointResult(host="unknown", url=match.group(1), method="GET", source_tool=self.name))
        return results
