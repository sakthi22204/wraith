import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class KiterunnerTool(ReconTool):
    def __init__(self):
        super().__init__(name="kiterunner", image="kiterunner:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["kb", "scan", f"http://{domain}/api", "-w", "/wordlists/routes-small.kite", "-o", "json"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                path = data.get("path") or data.get("url")
                if path:
                    host = "unknown"
                    if "://" in path:
                        parts = path.split("://")[1].split("/", 1)
                        host = parts[0]
                        path = "/" + parts[1] if len(parts) > 1 else "/"
                    results.endpoints.append(EndpointResult(host=host, url=path, method=data.get("method", "GET"), source_tool=self.name))
            except json.JSONDecodeError:
                continue
        return results
