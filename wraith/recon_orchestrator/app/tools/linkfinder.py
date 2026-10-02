import re
from typing import List
from .base import ReconTool, absolute_url, host_from_domain, iter_path_or_url_lines
from ..schemas import ToolResults, EndpointResult

class LinkfinderTool(ReconTool):
    """Parses `linkfinder -o cli`.

    The output is one result per line -- a bare path (`/admin`) or an absolute
    URL -- but stdout and stderr are merged, so the tool's own logfmt warnings
    arrive on the same stream. A result is therefore required to be the whole
    line; searching each line for a path anywhere in it is what turned a
    diagnostic's `Config file /root/.gau.toml not found` into an endpoint
    attributed to the target.
    """

    def __init__(self):
        super().__init__(name="linkfinder", image="linkfinder:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-i", f"http://{domain}", "-o", "cli"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for candidate in iter_path_or_url_lines(output):
            match = re.search(r'(?:https?://[a-zA-Z0-9\.-]+)?(/[a-zA-Z0-9\.-_/]+)', candidate)
            if match:
                # A match on another origin is recorded verbatim; a match on
                # the target is a path and needs the target re-attached.
                full = absolute_url(match.group(1), domain)
                results.endpoints.append(EndpointResult(host=host_from_domain(full) or host_from_domain(domain) or "unknown", url=full, method="GET", source_tool=self.name))
        return results
