import re
from typing import List, Optional
from .base import ReconTool, absolute_url, host_from_domain
from ..schemas import ToolResults, EndpointResult

# A block header: "[ + ] URL: http://host/path". Everything under it until the
# next header describes secrets found in that one file.
_URL_BLOCK = re.compile(r"^\s*\[\s*[+*]\s*\]\s*URL\s*:\s*(\S+)\s*$")

# A finding: "<name>\t->\t<value>". The value is captured only to confirm the
# line is well formed; it is deliberately discarded and never stored. See below.
_FINDING = re.compile(r"^\s*(?P<name>[^\t]+?)\s*->\s*(?P<value>\S.*?)\s*$")


class SecretfinderTool(ReconTool):
    """Parses `secretfinder -o cli`.

    The output is a sequence of blocks, one per file that was scanned:

        [ + ] URL: http://host/static/app.js
        google_api   ->   AIza...
        slack_token  ->   xoxb...

    With `-e` the input is a page, so every JavaScript file linked from it gets
    its own block. The header therefore matters: it is the only thing tying a
    secret to the file it came from.
    """

    def __init__(self):
        super().__init__(name="secretfinder", image="secretfinder:latest")

    def get_command(self, domain: str) -> List[str]:
        return ["-i", f"http://{domain}", "-e", "-o", "cli"]

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        current_url: Optional[str] = None
        seen = set()

        for raw in output.splitlines():
            line = raw.rstrip()
            if not line.strip():
                continue

            block = _URL_BLOCK.match(line)
            if block:
                current_url = block.group(1)
                continue

            finding = _FINDING.match(line)
            if not finding:
                continue

            name = finding.group("name").strip()
            if not name:
                continue

            if not current_url:
                # A finding with no block header cannot be attributed to a file,
                # so there is nothing actionable to record. Inventing a URL
                # would put a node in the graph that does not exist on the
                # target, which is worse than reporting nothing: it looks like
                # something to go and check. Say so instead, and do not keep the
                # value.
                results.notes.append(
                    f"{self.name}: reported a '{name}' with no source file; "
                    "not attributable, value discarded"
                )
                continue

            key = (current_url, name.lower())
            if key in seen:
                continue
            seen.add(key)

            results.endpoints.append(EndpointResult(
                host=host_from_domain(current_url) or host_from_domain(domain) or "unknown",
                url=current_url,
                method="GET",
                source_tool=self.name,
            ))
            # The secret *type* and the file it lives in. The value is never
            # stored: a graph of findings is long-lived, gets exported into
            # reports, and is copied around, so a live credential written into
            # one becomes a liability that outlives the engagement. The note
            # says what to go and look for; fetching the URL is the
            # confirmation step.
            results.notes.append(f"{self.name}: '{name}' exposed in {current_url}")

        return results
