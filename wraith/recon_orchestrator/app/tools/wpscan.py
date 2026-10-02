import json
from typing import List
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

class WpscanTool(ReconTool):
    def __init__(self):
        super().__init__(name="wpscan", image="wpscanteam/wpscan:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["--url", f"http://{domain}", "--format", "json"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        try:
            data = json.loads(output)
            host = host_from_domain(domain) or "unknown"
            for plugin_name in data.get("plugins", {}).keys():
                url = absolute_url(f"/wp-content/plugins/{plugin_name}/", domain)
                results.endpoints.append(EndpointResult(host=host_from_domain(url) or host, url=url, method="GET", source_tool=self.name))
            for theme_name in data.get("themes", {}).keys():
                url = absolute_url(f"/wp-content/themes/{theme_name}/", domain)
                results.endpoints.append(EndpointResult(host=host_from_domain(url) or host, url=url, method="GET", source_tool=self.name))
        except Exception:
            pass
        return results
