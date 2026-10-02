import json
from typing import Dict, List, Optional, Set
from .base import ReconTool, host_from_domain
from ..schemas import ToolResults, EndpointResult

# Statuses ffuf reports for a hit. A 200/3xx means something answered; a 401/403
# means the resource exists but is gated, which is exactly the kind of endpoint
# worth keeping. 404 is not a hit at all.
_HIT_STATUSES = {200, 201, 204, 301, 302, 307, 401, 403, 405, 500}


def _is_wordlist_comment(url: str) -> bool:
    """True when the "path" is a comment from the wordlist, not a probe.

    The bundled wordlist opens with a licence line::

        # Curated subset of SecLists' Discovery/Web-Content/common.txt

    ffuf substitutes that verbatim, so the run contains a hit for a path
    beginning ``#`` that no attacker would ever request. It arrives as a
    perfectly well-formed URL, so nothing downstream can tell it apart from a
    real result -- it was persisted as an Endpoint, entered the graph, and
    became CORS and Host-header candidates. A fragment is not part of what the
    server is asked for either, so it is dropped on the same grounds.
    """
    path = url.split("://", 1)[-1].split("/", 1)[-1]
    return path.lstrip().startswith("#")


class FfufTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="ffuf", image="ffuf/ffuf:latest")

    def get_command(self, domain: str) -> List[str]:
        return [
            "-u", f"http://{domain}/FUZZ",
            "-w", "/wordlists/common.txt",
            "-json",
            # Ask ffuf to suppress the baseline response rather than record it.
            # Every response sharing the baseline's size and status is the
            # target's catch-all, not a discovered path.
            "-fs", "0",
        ]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        # A single-page app answers 200 with an identical body for every path,
        # so a wordlist sweep over one returns the whole wordlist as "found".
        # ffuf reports that shape as every line sharing one status/length; those
        # lines are recorded as noise here and the target is noted instead, so
        # a consumer can tell "fuzzed, nothing distinct" from "never ran".
        records: List[Dict] = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = data.get("url")
            if url:
                records.append(data)

        if not records:
            return results

        by_shape: Dict[tuple, int] = {}
        for data in records:
            shape = (data.get("status"), data.get("length"))
            by_shape[shape] = by_shape.get(shape, 0) + 1
        # If one response shape accounts for most of the hits, that shape is the
        # target answering everything the same way. One lone 401 in a run of
        # identical 200s is still a real signal, so the threshold is a majority
        # rather than "any repeat".
        dominant, dominant_n = max(by_shape.items(), key=lambda kv: kv[1])
        uniform = len(records) > 2 and dominant_n >= max(2, len(records) // 2)

        seen: Set[str] = set()
        for data in records:
            url = data.get("url") or ""
            if _is_wordlist_comment(url):
                continue
            status = data.get("status")
            if isinstance(status, int) and status not in _HIT_STATUSES:
                continue
            if uniform and (data.get("status"), data.get("length")) == dominant:
                continue
            if url in seen:
                continue
            seen.add(url)
            # ffuf already reports the full URL it matched. Keep it: a bare path
            # cannot be scoped or probed downstream, and splitting it here is
            # what made every fuzzed path unattributable to a target.
            host = host_from_domain(url) or host_from_domain(domain) or "unknown"
            results.endpoints.append(EndpointResult(
                host=host, url=url, method="GET", source_tool=self.name
            ))

        if uniform:
            results.notes.append(
                f"ffuf: {dominant_n} of {len(records)} hits shared status "
                f"{dominant[0]} and length {dominant[1]}; treated as a "
                f"catch-all response and suppressed. Re-check with a filter "
                f"matched on content, not size."
            )
        return results
