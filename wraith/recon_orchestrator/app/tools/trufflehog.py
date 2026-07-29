import re
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class TrufflehogTool(ReconTool):
    def __init__(self):
        super().__init__(name="trufflehog", image="trufflehog:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["git", f"http://{domain}"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if "leak" in line.lower() or "secret" in line.lower() or "found" in line.lower():
                results.endpoints.append(EndpointResult(host="unknown", url=f"/trufflehog-finding", method="GET", source_tool=self.name))
        return results
