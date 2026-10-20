import json
from typing import List
from .base import ReconTool, target_url, absolute_url, host_from_domain
from .proxy import add_proxy_flags
from ..schemas import ToolResults, EndpointResult

class KatanaTool(ReconTool):
    # Bounded crawl: the wall-clock budget must exceed -crawl-duration plus time
    # to wind down and emit JSON, or the spawner abandons the container. The
    # crawl itself is capped at 180s -- a recon session that lets one tool sit
    # for 10 minutes on every target turns the whole run into a crawl queue,
    # and the routes worth having (API paths, parameterised endpoints) show up
    # in the first minutes of a pass.
    timeout = 300
    # katana self-terminates so it never outlives its budget (and leak an
    # orphaned container when a large site is crawled at a low CPU quota).
    crawl_duration = "180s"
    # Two vCPUs, like the other stateful tools: at the shared 0.5-CPU default a
    # crawl spends most of its 300s budget preempted rather than crawling.
    cpu_quota = 100000

    def __init__(self):
        super().__init__(name="katana", image="projectdiscovery/katana:latest")

    def get_command(self, domain: str) -> List[str]:
        # -u domain, -j for JSON output (katana uses -j not -json)
        # -crawl-duration bounds the run; -depth bounds how deep the crawl
        # descends (3: seed pages, their links, and one level past those --
        # enough for API routes without turning a marketing site into a
        # full-site mirror); -proxy routes egress through the intercepting
        # sidecar when enabled (Go tools resolve the single-label sidecar host
        # via extra_hosts).
        return add_proxy_flags(
            ["-u", target_url(domain), "-j", "-silent",
             "-crawl-duration", self.crawl_duration,
             "-depth", "3"],
            "-proxy",
        )

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                request = data.get("request", {})
                # katana outputs "endpoint" not "url", and it may be a path
                # relative to the crawl root when the seed had no scheme.
                url = absolute_url(
                    request.get("endpoint") or request.get("url") or "", domain
                )
                method = request.get("method", "GET")
                if url:
                    host = host_from_domain(url) or host_from_domain(domain) or "unknown"
                    results.endpoints.append(EndpointResult(
                        host=host,
                        url=url,
                        method=method,
                        source_tool=self.name
                    ))
            except json.JSONDecodeError:
                continue
        return results
