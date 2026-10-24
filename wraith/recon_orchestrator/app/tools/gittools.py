import re
from typing import List
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

# GitTools' Finder prints a banner on every run::

#     # Finder is part of https://github.com/internetwache/GitTools
#     ...
#     Scanning...
#     [*] Found: example.com
#     Finished

# The banner contains "GitTools", "git" and "Finder" even when the scan finds
# nothing. Matching the substring "git" therefore reported `/.git/` on every
# target, and recon aimed nuclei at that invented endpoint. On the Juice Shop
# run the false positive was `http://juice_shop/.git/` on port 80 -- a dead
# service -- and each template then burned its timeout against it: one pass took
# 30 minutes and was killed. The only line that is evidence is the one Finder
# prints for a match.
_FOUND_LINE = re.compile(r"\[\*\]\s*Found:\s*(\S+)", re.IGNORECASE)


class GittoolsTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="gittools", image="gittools:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-u", f"http://{domain}"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        # Each match line names the host Finder confirmed a `.git/HEAD` with
        # `refs/heads` in it. Use that host rather than the domain we were
        # given: it carries the port when the target answered on one, so the
        # endpoint lands on the authority that actually served it.
        for match in _FOUND_LINE.finditer(output or ""):
            host = match.group(1).strip().rstrip("/")
            if not host:
                continue
            url = absolute_url("/.git/", host)
            results.endpoints.append(EndpointResult(
                host=host_from_domain(url) or host_from_domain(domain) or "unknown",
                url=url,
                method="GET",
                source_tool=self.name,
            ))
        return results
