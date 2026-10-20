import json
from typing import List, Optional
from .base import ReconTool, target_url, host_from_domain
from .proxy import add_proxy_flags
from ..schemas import ToolResults, EndpointResult

class HttpxProbeTool(ReconTool):
    def __init__(self):
        # Using official image. Note: projectdiscovery/httpx
        super().__init__(name="httpx", image="projectdiscovery/httpx:latest")

    def get_command(self, domain: str, extra_urls: Optional[List[str]] = None) -> List[str]:
        # -u target(s), -json output, -silent. With a port batch the extra URLs
        # ARE the probe set -- the discovered port URLs, one comma-joined -u in
        # a single container instead of one container per port. Without them the
        # command is byte-identical to the bare-host probe it has always been.
        if extra_urls:
            targets: List[str] = []
            seen = set()
            for url in extra_urls:
                if url and url not in seen:
                    seen.add(url)
                    targets.append(url)
        else:
            targets = [target_url(domain)]
        return add_proxy_flags(
            ["-u", ",".join(targets), "-json", "-silent"], "-http-proxy"
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
