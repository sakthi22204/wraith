import json
from typing import List
from .base import ReconTool
from ..schemas import ToolResults, EndpointResult

class WpscanTool(ReconTool):
    def __init__(self):
        super().__init__(name="wpscan", image="wpscanteam/wpscan:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["--url", f"http://{domain}", "--format", "json"]

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        try:
            data = json.loads(output)
            for plugin_name in data.get("plugins", {}).keys():
                results.endpoints.append(EndpointResult(host="unknown", url=f"/wp-content/plugins/{plugin_name}/", method="GET", source_tool=self.name))
            for theme_name in data.get("themes", {}).keys():
                results.endpoints.append(EndpointResult(host="unknown", url=f"/wp-content/themes/{theme_name}/", method="GET", source_tool=self.name))
        except Exception:
            pass
        return results
