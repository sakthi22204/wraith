from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class GittoolsTool(ReconTool):
    def __init__(self):
        super().__init__(name="gittools", image="gittools:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-u", f"http://{domain}"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        if "found" in output.lower() or "exposed" in output.lower() or "git" in output.lower():
            results.endpoints.append(EndpointResult(host="unknown", url="/.git/", method="GET", source_tool=self.name))
        return results
