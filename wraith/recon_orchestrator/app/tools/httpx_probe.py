import json
from typing import List
from .base import ReconTool, target_url, host_from_domain
from .proxy import add_proxy_flags
from ..schemas import ToolResults, EndpointResult

class HttpxProbeTool(ReconTool):
    def __init__(self):
        # Using official image. Note: projectdiscovery/httpx
        super().__init__(name="httpx", image="projectdiscovery/httpx:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -json output, -silent
        return add_proxy_flags(
            ["-u", target_url(domain), "-json", "-silent"], "-http-proxy"
        )

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url")
                method = data.get("method", "GET")
                if url:
                    # httpx reports the full URL. Its "host" field is the bare
                    # name; prefer the URL's own authority, and never fall back
                    # to "unknown" while the target we scanned is in hand.
                    host = (
                        host_from_domain(url)
                        or host_from_domain(data.get("host") or "")
                        or host_from_domain(domain)
                        or "unknown"
                    )
                    results.endpoints.append(EndpointResult(
                        host=host,
                        url=url,
                        method=method,
                        source_tool=self.name
                    ))
            except json.JSONDecodeError:
                continue
        return results
