import re
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class SecretfinderTool(ReconTool):
    def __init__(self):
        super().__init__(name="secretfinder", image="secretfinder:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-e", f"http://{domain}", "-o", "cli"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if "token" in line.lower() or "key" in line.lower() or "secret" in line.lower():
                results.endpoints.append(EndpointResult(host="unknown", url=f"/secret-disclosure-{self.name}", method="GET", source_tool=self.name))
        return results
