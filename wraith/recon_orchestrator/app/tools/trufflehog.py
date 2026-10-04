import json
from typing import List
from .base import ReconTool, host_from_domain
from ..schemas import ToolResults, EndpointResult

class TrufflehogTool(ReconTool):
    # Slow fan-out tool: needs more than the global TOOL_TIMEOUT budget.
    timeout = 600
    def __init__(self):
        super().__init__(name="trufflehog", image="trufflesecurity/trufflehog:latest")

    def get_command(self, domain: str) -> List[str]:
        # --json is required for correctness. The previous parser ran on
        # trufflehog's human-readable output and substring-matched
        # "found"/"leak"/"secret" anywhere in a line, which cannot distinguish a
        # real detection from a banner, a progress line or a filename. It then
        # emitted http://<domain>/trufflehog-finding -- a URL that does not exist
        # -- for every hit. Those invented URLs were persisted as assets and went
        # on to seed validation candidates, so a finding could have been reported
        # against a URL this pipeline made up.
        return ["git", "--json", f"http://{domain}"]

    def _http_url(self, payload: dict):
        """Return a real URL from the result metadata, or None.

        Most hits from `trufflehog git` come from the repository contents, not
        from an HTTP response, and have no URL at all. Those are not endpoints
        and must not be turned into one.
        """
        data = (payload.get("SourceMetadata") or {}).get("Data") or {}
        for key in ("HTTP", "Http"):
            http = data.get(key)
            if isinstance(http, dict):
                url = http.get("URL") or http.get("Url") or http.get("url")
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    return url
        # Filesystem-sourced results can carry the file they came from; that is
        # a path on a remote, not a route we can request.
        return None

    def _location(self, payload: dict) -> str:
        data = (payload.get("SourceMetadata") or {}).get("Data") or {}
        for key in ("Git", "Filesystem", "GitHub"):
            section = data.get(key)
            if isinstance(section, dict):
                parts = [
                    str(section[field])
                    for field in ("repository", "repo", "file", "path", "line", "link")
                    if section.get(field)
                ]
                if parts:
                    return " ".join(parts)
        return ""

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        seen = set()
        unverified = 0
        verified = 0
        unparsed = 0

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except (ValueError, TypeError):
                # Plain-text progress output, or a line that is not a result.
                # Counting it is enough; it must never become an endpoint.
                unparsed += 1
                continue
            if not isinstance(payload, dict):
                unparsed += 1
                continue

            detector = payload.get("DetectorName") or "unknown"
            is_verified = bool(payload.get("Verified"))
            location = self._location(payload)

            if is_verified:
                verified += 1
            else:
                unverified += 1

            # The raw secret lives in payload["Raw"]. It is deliberately not
            # read, not logged and not stored: this pipeline records assets and
            # candidates, not credentials. Anyone needing the value should
            # re-run trufflehog themselves.
            results.notes.append(
                "trufflehog detector={} verified={}{}".format(
                    detector,
                    str(is_verified).lower(),
                    " location={}".format(location) if location else "",
                )
            )

            url = self._http_url(payload)
            if url and url not in seen:
                seen.add(url)
                results.endpoints.append(EndpointResult(
                    host=host_from_domain(url) or host_from_domain(domain) or "unknown",
                    url=url,
                    method="GET",
                    source_tool=self.name,
                ))

        if verified or unverified:
            results.notes.append(
                "trufflehog reported {} verified and {} unverified secret "
                "candidates; raw secret values were not recorded and only "
                "verified hits are worth pursuing".format(verified, unverified)
            )
        if unparsed:
            results.notes.append(
                "trufflehog emitted {} non-JSON lines which were ignored; no "
                "endpoint was synthesised from them".format(unparsed)
            )
        if not verified and not unverified:
            results.notes.append("trufflehog reported no secret candidates")
        return results