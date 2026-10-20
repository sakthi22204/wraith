import re
import socket
import ipaddress
from abc import ABC
from typing import List, Optional
from urllib.parse import urlsplit
from ..schemas import ToolResults, HostResult, PortResult, EndpointResult
from ..config import settings
from ..docker_spawner import (
    ToolDeadlineReached,
    ToolOOMKilled,
    docker_spawner,
)
from .proxy import proxy_env, proxy_volumes, proxy_extra_hosts


def target_url(target: str) -> str:
    """Convert a normalized host or host:port target into an HTTP URL."""
    return target if "://" in target else f"http://{target}"


def host_from_domain(domain: str) -> str:
    """Extract the bare hostname from a domain string (strip scheme, path, port).

    Parsed with urlsplit rather than by splitting on ``://``: archive tools
    return lines whose path contains a whole URL, e.g.
    ``https://tax.crypto.com/%20...https://koinly.io/``. Splitting on ``://``
    and taking the last piece attributes that endpoint to ``koinly.io``, putting
    an unrelated third party into the graph as if it were a discovered host.
    urlsplit keeps the real authority and treats the rest as a path.
    """
    candidate = (domain or "").strip()
    if not candidate:
        return ""
    try:
        parsed = urlsplit(candidate if "//" in candidate else f"//{candidate}")
    except ValueError:
        return ""
    return (parsed.hostname or "").lower()


# A whole line that is nothing but an absolute http(s) URL. Quotes, spaces and
# angle brackets are excluded because every logfmt diagnostic these tools emit
# is `time=... level=... msg="..."`, and the msg values routinely contain both.
_URL_LINE = re.compile(r"^https?://[^\s\"'<>]+$", re.IGNORECASE)


def iter_url_lines(output: str):
    """Yield only the lines of a tool's merged output that really are URLs.

    Containers are spawned without separating stdout from stderr, so a tool's
    progress and warnings arrive interleaved with its results. Treating every
    non-empty line as a URL is how a gau config warning became a Host in the
    graph (`time="2026-10-02T07;`) and then an endpoint built out of the middle
    of that same warning.
    """
    for line in (output or "").splitlines():
        candidate = line.strip()
        if _URL_LINE.match(candidate):
            yield candidate


# The same discipline for tools that report a bare path (`/admin`) rather than a
# whole URL. Here a result has to be the *entire* line, because the failure mode
# is a path being mined out of the middle of a diagnostic: linkfinder's merged
# stream carried `... Config file /root/.gau.toml not found`, and a substring
# search turned that config path into an endpoint attributed to the target.
_PATH_OR_URL_LINE = re.compile(
    r"^(?:https?://[^\s\"'<>]+|/[\w\-./~%:@!$&()*+,;=?#]*)$",
    re.IGNORECASE,
)


def iter_path_or_url_lines(output: str):
    """Yield only the lines of a tool's output that are wholly a path or a URL."""
    for line in (output or "").splitlines():
        candidate = line.strip()
        if candidate and _PATH_OR_URL_LINE.match(candidate):
            yield candidate


def absolute_url(path: str, domain: str) -> str:
    """Qualify a discovered path with the target it was found on.

    Most of these tools report what they matched as a path (``/login``) with the
    host living only in the tool's invocation. The host is not a detail here:
    ``EndpointResult.url`` is what the hypothesis generator, the graph and the
    agent all treat as the endpoint's address, and a bare path is not a usable
    one -- it cannot be scoped, probed, or attributed to a target. A tool that
    drops the host silently drops the endpoint from the rest of the pipeline.
    """
    if not path:
        return ""
    if "://" in path:
        return path
    if not domain:
        return path
    if path.startswith("//"):
        # Protocol-relative: keep it relative but re-anchor the authority.
        return f"http:{path}"
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{target_url(domain).rstrip('/')}{path}"


def resolve_extra_hosts(domain: str) -> Optional[dict]:
    """Best-effort hostname -> IP mapping so Go-based tools can resolve
    Docker-internal single-label names (e.g. naabu scanning 'juice_shop').
    Non-fatal: if resolution fails the tool container falls back to its own DNS."""
    host = host_from_domain(domain)
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        return {host: socket.gethostbyname(host)}
    except OSError:
        return None


class ReconTool(ABC):
    # Per-tool wall-clock budget in seconds. None -> settings.TOOL_TIMEOUT.
    # Tools that fan out across many archive/DNS sources (gau, waybackurls,
    # dnsx, ...) can exceed the global budget when the broker caps them at
    # settings.CPU_QUOTA, so they declare a larger one here.
    timeout: Optional[int] = None

    def __init__(self, name: str, image: Optional[str] = None):
        self.name = name
        # None means "this tool does its work in this process instead of in a
        # broker-spawned container". That is a deliberate exception to how every
        # other tool runs, so it is opt-in per tool rather than a general
        # capability: an in-process tool reaches the network directly and bypasses
        # the broker's image allowlist, so only a tool that merely *parses* what
        # the target already serves may use it. Such a tool must scope its own
        # fetches -- see js_routes.JsRoutesTool for what that has to mean.
        self.image = image

    # True for a tool whose command is built from discovered endpoints, not just
    # from the seed target. See run() for why this is opt-in.
    accepts_extra_urls: bool = False

    def get_command(self, domain: str, extra_urls: Optional[List[str]] = None) -> List[str]:
        raise NotImplementedError(
            f"{self.name} is an in-process tool and has no container command"
        )

    def parse_output(self, output: str, domain: str = "") -> ToolResults:
        raise NotImplementedError(f"{self.name} does not parse container output")

    async def run_in_process(self, domain: str) -> ToolResults:
        raise NotImplementedError(
            f"{self.name} declares no image but implements no in-process run"
        )

    async def run(self, domain: str, extra_urls: Optional[List[str]] = None,
                  force_extra: bool = False) -> ToolResults:
        """Run the tool. ``extra_urls`` are endpoints already discovered on
        ``domain`` that the tool may want to aim at individually.

        Only tools that opt in via ``accepts_extra_urls`` see them; every other
        tool's command is byte-identical to what it was before. The exception
        is ``force_extra``, which a caller sets for a batch run whose whole
        purpose is the extra list (httpx re-aimed at discovered ports) -- the
        tool then consumes it without having to declare it for every run.
        """
        if self.image is None:
            return await self.run_in_process(domain)
        # Only a tool that opted in (or was explicitly forced) is called with
        # the extra argument, and only when there is something to pass. Every
        # other tool's get_command is invoked exactly as before, so its
        # signature stays get_command(domain).
        if extra_urls and (force_extra or self.accepts_extra_urls):
            cmd = self.get_command(domain, extra_urls)
        else:
            cmd = self.get_command(domain)
        merged_hosts = {}
        eh = resolve_extra_hosts(domain)
        if eh:
            merged_hosts.update(eh)
        merged_hosts.update(proxy_extra_hosts())
        try:
            raw_output = await docker_spawner.spawn_container(
                self.image, cmd,
                timeout=self.timeout or settings.TOOL_TIMEOUT,
                extra_hosts=merged_hosts or None,
                environment=proxy_env(),
                volumes=proxy_volumes(),
                mem_limit=getattr(self, "mem_limit", None),
                cpu_quota=getattr(self, "cpu_quota", None),
            )
        except ToolDeadlineReached as e:
            return self._aborted(e.logs, domain, timed_out=True)
        except ToolOOMKilled as e:
            return self._aborted(e.logs, domain, timed_out=False)
        return self.parse_output(raw_output, domain)

    def _aborted(self, logs: str, domain: str, timed_out: bool) -> ToolResults:
        """Parse what an aborted container flushed, and say why it stopped.

        The partial output is evidence: a deadline-stopped scan that found
        three things before the cut-off still found three things. The flag is
        what lets the orchestrator mark the attempt TIMED_OUT (or OOM-failed)
        instead of retrying a budget -- or a memory limit -- that will not fit
        the same command any better the second time.
        """
        results = self.parse_output(logs, domain)
        if timed_out:
            results.timed_out = True
            results.notes.append(
                f"{self.name} was stopped at its wall-clock budget; "
                f"partial output kept"
            )
        else:
            results.oom_killed = True
            results.notes.append(
                f"{self.name} was killed for exceeding its memory limit"
            )
        return results
