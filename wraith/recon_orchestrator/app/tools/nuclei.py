import json
from typing import List, Optional
from .base import ReconTool, target_url, host_from_domain, absolute_url
from ..schemas import ToolResults, EndpointResult, FindingResult
from ..config import settings
from .proxy import add_user_agent_flag

# Template tags to run.
#
# These ARE active checks -- sqli sends injection payloads, cve probes for known
# holes, default-login tries a credential list. That is the point of the tool,
# and it is why it must never run against a remote target: the orchestrator's
# `not remote` gate is the control, not this list.
#
# An earlier revision of this file passed only `tech,misc,exposure,default-login`
# on the theory that read-only tags were safer. That scans for exactly nothing
# useful: against the local Juice Shop it returned 0 matches, because the
# application is not misconfigured -- it is injectable. A tag list that excludes
# the vulnerability templates makes the scanner a slower way of asking httpx
# whether the port is open. Do not narrow this back to passive tags.
SCAN_TAGS = "tech,misc,exposure,default-login,sqli,cve,misconfig"


class NucleiTool(ReconTool):
    """Vulnerability checks with nuclei templates, against a local target only.

    Scheduled exclusively for Docker-local targets by the orchestrator (it is in
    AGGRESSIVE_TOOLS and absent from PASSIVE_REMOTE_TOOLS, so a remote run marks
    it SKIPPED before anything is dispatched). A template run against a real
    program would be active traffic that no ROE in this system authorizes, so the
    local-only scheduling is the control, not a convenience.
    """

    # nuclei fans out one request per template per URL. -max-time is what bounds
    # the run (there is no -crawl-duration in nuclei; that is a katana flag, and
    # passing it makes nuclei exit 1 having scanned nothing). It must land inside
    # this budget so the spawner does not abandon the container mid-write.
    #
    # The budget bounds *one pass*. A pass that hits -max-time keeps its partial
    # output (the orchestrator marks it TIMED_OUT and does not retry), so a cap
    # costs coverage of the tail, not the work already done. The earlier 1800s
    # broker budget let a single dead-target pass occupy the whole session: one
    # Juice Shop run spent 30 minutes timing out against `http://juice_shop`
    # (port 80, closed). With a known-good target the first pass finishes in
    # ~6 minutes at this tool's 2-CPU quota, so 900s is generous for that and
    # still caps a pathological pass at 15 minutes; the broker deadline sits
    # above it to let nuclei flush.
    timeout = 1200
    max_time = "900s"

    # The broker's default 512MiB limit OOM-kills nuclei. Loading and clustering
    # the template set (this image ships ~14000 yaml) needs more than that; a
    # `--memory 512m` run is SIGKILLed at ~20s with zero output while a 2G run
    # of the same command exits 0 and reports matches. Declared per-tool because
    # a port scanner does not deserve the same headroom.
    mem_limit = "2g"
    cpu_quota = 200000

    # A template only fires against a URL it is actually pointed at. Given just
    # the seed target, nuclei tests the homepage and whatever the homepage links
    # to, so an injection behind a query string on a route nothing links to
    # (/rest/products/search?q=) is never requested. Feeding it the discovered
    # endpoint list is the difference between scanning and not scanning.
    accepts_extra_urls = True

    # One scan at a time against a given target, and never twice over the same
    # URL set. The trigger keys on route count, so every tool that widens the
    # surface (katana, js_routes, ffuf, linkfinder) schedules another pass while
    # the previous one may still be running; six concurrent nuclei processes
    # against one local container pushed Juice Shop from 220MiB to its 6GiB
    # limit, at which point the target stopped answering and every scan in
    # flight reported "0 findings". Serialized, the target stays responsive and
    # each pass sees the full route set discovered so far.
    serialize_per_target = True
    dedupe_scanned_urls = True

    def __init__(self):
        super().__init__(name="nuclei", image="nuclei:latest")

    # How many discovered endpoints to hand over. nuclei issues one request per
    # template per URL, so this multiplies runtime; the cap keeps a large SPA's
    # route table from turning one trigger into thousands of scans.
    max_targets = 150

    def get_command(self, domain: str, extra_urls: Optional[List[str]] = None) -> List[str]:
        # -jsonl for parseable output, -duc to skip the template-update network
        # call (the image ships its templates; an update attempt in a container
        # with no route out just stalls), -no-color and -silent so stdout is only
        # findings.
        targets = self._targets(domain, extra_urls)
        # One comma-separated -u, verified to fan out across every URL in the
        # list. A -l target file would need a host path or volume mount, and the
        # broker allows neither, so file-based target lists are unavailable here.
        return add_user_agent_flag(["-u", ",".join(targets)] + [
            "-jsonl",
            "-silent",
            "-duc",
            "-no-color",
            # OAST templates register a callback domain and wait for a connection
            # from a third-party server. That is an outbound request the operator
            # did not ask for and evidence that leaves this host, so the whole
            # interactsh path is off.
            "-no-interactsh",
            "-tags", SCAN_TAGS,
            # No `-severity` filter. The templates this tag set selects are
            # mostly *info* severity by design -- tech fingerprinting, exposures
            # and misc checks -- so a severity floor removes exactly the
            # reportable matches while leaving the scan looking like it ran.
            # Tag selection is the scope control here; severity is not.
            "-rate-limit", str(settings.RECON_REQUEST_RATE_LIMIT),
            "-timeout", "10",
            "-retries", "1",
            "-max-time", self.max_time,
        ], "-H")

    def _targets(self, domain: str, extra_urls: Optional[List[str]]) -> List[str]:
        """The seed target plus discovered endpoints, deduped and capped.

        Only http(s) URLs on the seed's own host are kept. A discovered endpoint
        can carry a third-party authority -- linkfinder extracts full URLs out of
        a JavaScript bundle -- and handing a scanner someone else's URL turns a
        scoped scan into traffic aimed at a host the program never authorized.
        Fragments are stripped: nuclei matches on the request it sends, and a
        fragment is not part of it.
        """
        seed_host = (host_from_domain(domain) or "").lower()
        seed = target_url(domain).rstrip("/")
        out: List[str] = [seed]
        seen = {seed}
        for raw in (extra_urls or []):
            url = absolute_url(str(raw or "").strip(), domain)
            if not url.lower().startswith(("http://", "https://")):
                continue
            clean = url.split("#", 1)[0].rstrip("/")
            if not clean or clean in seen:
                continue
            if seed_host and (host_from_domain(clean) or "").lower() != seed_host:
                continue
            seen.add(clean)
            out.append(clean)
            if len(out) >= self.max_targets:
                break
        return out

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        results = ToolResults()
        for line in (output or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = str(data.get("template-id") or data.get("templateID") or "").strip()
            info = data.get("info") or {}
            matched_at = data.get("matched-at") or data.get("matched") or data.get("host") or ""
            if not matched_at:
                results.notes.append(f"nuclei match {template_id or '(unnamed)'} had no matched-at URL; skipped")
                continue
            if not template_id:
                results.notes.append(f"nuclei match at {matched_at} carried no template id; skipped")
                continue

            matched_host = (
                host_from_domain(str(matched_at))
                or host_from_domain(domain)
                or "unknown"
            )
            method = str(data.get("request-method") or data.get("method") or "GET").upper()
            results.endpoints.append(EndpointResult(
                host=matched_host,
                url=str(matched_at),
                method=method,
                source_tool=self.name,
            ))
            severity = str(info.get("severity") or "unknown")
            name = str(info.get("name") or template_id)
            # A match is a finding, not just an endpoint. Endpoints alone left
            # the investigation's findings view empty on an application the
            # scanner had flagged; the graph now gets a Finding attached to the
            # endpoint it was matched at.
            results.findings.append(FindingResult(
                host=matched_host,
                url=str(matched_at),
                method=method,
                source_tool=self.name,
                vuln_type=template_id,
                severity=severity,
                title=name,
                description=str(info.get("description") or "").strip(),
                template_id=template_id,
                evidence=f"nuclei template '{template_id}' matched at {matched_at}",
            ))
            results.notes.append(
                f"nuclei matched template '{template_id}' ({name}, severity={severity}) "
                f"at {matched_at}"
            )
        return results
