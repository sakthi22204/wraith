import json
from typing import List
from .base import ReconTool, target_url
from .proxy import add_proxy_flags
from ..schemas import ToolResults, EndpointResult

class KatanaTool(ReconTool):
    # Deep crawl: budget must exceed katana's own -crawl-duration cap plus
    # time to wind down and emit JSON, or the spawner abandons the container.
    timeout = 900
    # katana self-terminates so it never outlives its budget (and leak an
    # orphaned container when a large site is crawled at a low CPU quota).
    crawl_duration = "600s"

    def __init__(self):
        super().__init__(name="katana", image="projectdiscovery/katana:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -j for JSON output (katana uses -j not -json)
        # -crawl-duration bounds the run; -proxy routes egress through the
        # intercepting sidecar when enabled (Go tools resolve the single-label
        # sidecar host via extra_hosts).
        return add_proxy_flags(
            ["-u", target_url(domain), "-j", "-silent",
             "-crawl-duration", self.crawl_duration],
            "-proxy",
        )

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
