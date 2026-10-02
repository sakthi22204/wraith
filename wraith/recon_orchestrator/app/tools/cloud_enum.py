import re
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, HostResult

class CloudEnumTool(ReconTool):
    def __init__(self):
        super().__init__(name="cloud_enum", image="cloud_enum:latest")

    def get_command(self, domain: str) -> List[str]:
        keyword = domain.split(".")[0]
        return ["-k", keyword]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if "OPEN" in line or "MUTATION" in line:
                match = re.search(r'(?:https?://)?([a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})', line)
                if match:
                    results.hosts.append(HostResult(value=match.group(1), source_tool=self.name))
        return results
