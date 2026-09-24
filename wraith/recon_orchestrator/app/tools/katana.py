import json
from typing import List
from .base import ReconTool, target_url
from .proxy import add_proxy_flags
from ..schemas import ToolResults, EndpointResult

class KatanaTool(ReconTool):
    def __init__(self):
        super().__init__(name="katana", image="projectdiscovery/katana:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -j for JSON output (katana uses -j not -json)
        # -proxy routes egress through the intercepting sidecar when enabled
        # (Go tools resolve the single-label 'mitmproxy' via extra_hosts).
        return add_proxy_flags(["-u", target_url(domain), "-j", "-silent"], "-proxy")

    def parse_output(self, output: str) -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                request = data.get("request", {})
                # katana outputs "endpoint" not "url"
                url = request.get("endpoint") or request.get("url")
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
