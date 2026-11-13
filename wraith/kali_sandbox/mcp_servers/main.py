import os
import json
from contextvars import ContextVar
from typing import Optional, List
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import BaseModel
from fastapi import HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from .nmap_server import NmapServer
from .nuclei_server import NucleiServer
from .sqlmap_server import SQLMapServer
from .hydra_server import HydraServer
from .metasploit_server import MetasploitServer
from .web_tools_server import WebToolsServer
from .http_probe_server import HttpProbeServer
from .zap_server import ZapServer
from . import http_probe_server as http_probe_server_module
from .gate import GateError, authorization_context
from .config import validate_startup_secrets

# Create a single MCP server instance
mcp = FastMCP("Wraith Security Tools", host="0.0.0.0", port=8000)

caller_context: ContextVar[Optional[str]] = ContextVar("caller_context", default=None)

DANGEROUS_TOOLS = {"run_hydra", "run_msf_module"}

# Tools that send traffic to a caller-supplied destination. Each is gated on
# killswitch + signed grant + re-read scope, not merely on who the caller says
# it is: the request body chooses the destination, so a caller name proves
# nothing about where the packet is going.
#
# This list was previously the http_probe family only. run_nmap_scan,
# run_nuclei_scan, run_sqlmap, run_hydra and run_msf_module were dispatched on
# verify_caller alone, which is the request reading its own X-Wraith-Caller
# header. They are here now; `tests/test_ungated_tools.py` fails if a tool that
# sends traffic is ever added without being gated.
GATED_NETWORK_TOOLS = {
    "http_probe", "http_probe_diff", "http_probe_race", "http_probe_threshold",
    # Timing harness (median-of-N)
    "http_probe_timing",
    # Both of these open a raw socket and speak a protocol of their own rather
    # than following the URL, so the grant's host:port binding is what stops
    # them. Gating them is not optional for the same reason as the others: the
    # request decides the destination, and a caller name proves nothing about
    # where the bytes land.
    "http_probe_smuggle", "http_probe_websocket_auth",
    "run_nmap_scan", "run_nuclei_scan", "run_sqlmap", "run_hydra", "run_msf_module",
    # Phase 1.9 web scanners: arjun, dalfox, corsy, commix, ghauri, jwt_tool,
    # nikto, xsstrike. All of them take a caller-supplied URL (or, for
    # jwt_tool, a URL plus a token) and send traffic to it, so they are gated
    # on the same grant/scope chain as the rest -- a caller name proves nothing
    # about where the request lands.
    "run_arjun", "run_dalfox", "run_corsy", "run_commix", "run_ghauri",
    "run_jwt_tool", "run_nikto", "run_xsstrike",
    # ZAP runs in its own container and both modes fetch caller-supplied URLs
    # through ZAP's API. Baseline is passive, active sends payloads, but the
    # grant/scope binding is identical for both.
    "run_zap_baseline", "run_zap_active",
}
AUTHORIZED_DANGEROUS_CALLERS = set(os.getenv("AUTHORIZED_DANGEROUS_CALLERS", "active_exploit_runner").split(","))

# Metasploit option names that would redirect a module at a different host than
# the one the server set. msfconsole applies `set` commands left to right, and the
# sandbox emits `set RHOSTS <target>; <options>; run`, so an option named RHOSTS
# lands *after* it and wins. Refused rather than stripped: there is no way to tell
# a deliberate override from a mistake, and the destination belongs in `target`,
# which is what the grant is bound to.
RESERVED_HOST_OPTIONS = frozenset({"RHOST", "RHOSTS", "LHOST", "LHOSTS"})

# nmap_server.py's own default. Restated here so the gate describes the scan the
# server will actually run when the body names no ports. If the two drift, the
# claim stops matching the command line and the scan is refused rather than
# authorised at the wrong width.
NMAP_DEFAULT_PORTS = "1-1000"


def _nmap_port_claim(target: str, ports) -> str:
    """The ports an nmap run will dial, as nmap_server reads them.

    `nmap_server.run_nmap_scan` does `effective_ports = embedded_port or ports`,
    so a target carrying a port narrows the scan to that one. Mirrored exactly,
    because reporting the wider of the two here would authorise more than runs.
    """
    host, sep, port = str(target).rpartition(":")
    if sep and host and port.isdigit():
        return port
    if ports is None or not str(ports).strip():
        return NMAP_DEFAULT_PORTS
    return str(ports).strip()


def _nuclei_port_claim(target: str) -> str:
    """The port nuclei will dial for this target.

    `nuclei_server.run_nuclei_scan` passes `-u target` and no port flag, so the
    port comes from the target's own scheme. A bare host means port 80, which is
    what nuclei does with it.
    """
    candidate = str(target).strip()
    host, sep, port = candidate.rpartition(":")
    if sep and host and port.isdigit():
        return port
    if "://" in candidate:
        scheme = candidate.split("://", 1)[0].lower()
        default = {"http": 80, "https": 443, "ws": 80, "wss": 443}.get(scheme)
        if default:
            return str(default)
    return "80"


def verify_caller(tool_name: str, caller: Optional[str]):
    """Coarse caller pre-check; the gate is the real boundary.

    Dangerous tools (hydra, metasploit) are restricted to
    ``AUTHORIZED_DANGEROUS_CALLERS``. Every other tool only requires an
    identified caller, because what a caller may actually do is decided by
    ``gate_request``: a signed grant bound to the tool, a re-read scope, and --
    for the exploit agent -- the read-only floor in ``gate._check_tool``. This
    used to refuse every caller but the runner, which would have turned the
    agent's legitimate read-only calls into a 403 before the gate could judge
    them.
    """
    if tool_name in DANGEROUS_TOOLS:
        if caller not in AUTHORIZED_DANGEROUS_CALLERS:
            raise HTTPException(status_code=403, detail=f"Caller {caller} is not authorized to use {tool_name}")
    elif not caller:
        raise HTTPException(status_code=403, detail=f"Caller identity required for tool {tool_name}")

grant_context: ContextVar[Optional[str]] = ContextVar("grant_context", default=None)

# The gate's verified context for the request in flight. Set by gate_request so
# the probe tools can re-check a redirect hop against the same grant and scope
# rules, rather than each layer re-deriving them or skipping the check.
authorization_context_var: ContextVar[Optional[dict]] = ContextVar(
    "authorization_context", default=None)


def _destination_of(tool_name: str, body: dict) -> tuple[list[str], Optional[str]]:
    """Every URL a tool will send to, plus the port claim if it chooses its own.

    The body is what decides where the bytes go, so this is the whole of the
    gate's input. Each tool names its destination differently -- sqlmap reads
    `url`, nmap/hydra/msf read `target`, probes read `url` plus one per variant --
    and reading the wrong field scope-checks a value the tool never sends while
    the real destination rides through unchecked.

    The second element is the claim of "these are the ports I will dial", which
    is only ever set for a tool that picks its own ports. It used to be hardcoded
    to `None`, which meant the port half of a `host:port` grant was never
    actually checked: a grant for one port authorised nmap's default sweep.
    """
    body = body or {}
    targets: list[str] = []
    port_claim = None

    if tool_name in {"http_probe", "http_probe_diff", "http_probe_race",
                     "http_probe_threshold", "http_probe_timing",
                     "http_probe_smuggle", "http_probe_websocket_auth"}:
        if body.get("url"):
            targets.append(str(body["url"]))
        # Every variant is a separate request to a possibly separate host, so each
        # is checked on its own account rather than riding in on the baseline's.
        for variant in body.get("variants") or []:
            if isinstance(variant, dict) and variant.get("url"):
                targets.append(str(variant["url"]))
    elif tool_name == "run_sqlmap":
        if body.get("url"):
            targets.append(str(body["url"]))
    elif tool_name in {"run_arjun", "run_dalfox", "run_corsy", "run_commix",
                       "run_ghauri", "run_nikto", "run_xsstrike",
                       "run_zap_baseline", "run_zap_active"}:
        # Every one of these reads its destination from `url` and dials the
        # port the URL names, exactly like sqlmap/the probe family -- so no
        # port claim: the authority the grant binds already carries the port.
        if body.get("url"):
            targets.append(str(body["url"]))
    elif tool_name == "run_jwt_tool":
        # jwt_tool reads `target` (a URL) and sends the token to it in an
        # Authorization header; the token itself is data, never a destination.
        if body.get("target"):
            targets.append(str(body["target"]))
    elif tool_name in {"run_nmap_scan", "run_nuclei_scan", "run_hydra", "run_msf_module"}:
        if tool_name == "run_msf_module":
            options = body.get("options")
            if isinstance(options, dict):
                reserved = RESERVED_HOST_OPTIONS.intersection(options)
                if reserved:
                    raise ValueError(
                        "Metasploit options may not redirect the host: "
                        f"{', '.join(sorted(reserved))}; set the destination in 'target'"
                    )
        raw = body.get("target")
        if raw:
            targets.append(str(raw))

        if not targets:
            # Checked before the port claim, which reads targets[0]: an absent
            # destination has to surface as this ValueError rather than an
            # IndexError the caller is not expecting.
            raise ValueError(f"{tool_name} has no destination to check; refusing to send")

        if tool_name == "run_nmap_scan":
            # Read the ports exactly as the nmap server will: an embedded
            # `target:port` wins over the `ports` field, and an absent `ports`
            # means the server's own default. Reporting anything else here would
            # authorise a different scan from the one that runs.
            port_claim = _nmap_port_claim(targets[0], body.get("ports"))
        elif tool_name == "run_nuclei_scan":
            # nuclei takes no port parameter; it dials the scheme default for the
            # host it was given. So the claim is that single port, and a target
            # naming no port yields the default for whatever scheme it carries.
            port_claim = _nuclei_port_claim(targets[0])
    else:
        raise ValueError(f"no known destination field for tool {tool_name!r}")

    if not targets:
        raise ValueError(f"{tool_name} has no destination to check; refusing to send")

    return targets, port_claim


def gate_request(tool_name: str, body: dict, request=None):
    """Enforce killswitch, grant and scope before a gated tool sends anything."""
    if tool_name not in GATED_NETWORK_TOOLS:
        return
    from .config import settings
    caller = (request.headers.get("X-Wraith-Caller") if request is not None else None) or get_caller()
    grant_token = (request.headers.get("X-Wraith-Grant") if request is not None else None) or grant_context.get()
    try:
        targets, port_claim = _destination_of(tool_name, body)
    except ValueError as exc:
        # The tool cannot say where it is going, which is not a licence to guess.
        raise HTTPException(status_code=403, detail=str(exc))
    try:
        context = authorization_context(
            caller=caller, grant_token=grant_token, targets=targets,
            settings=settings, port_claim=port_claim, tool=tool_name,
        )
    except GateError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail)

    # Handed to the probe tools so a redirect hop can be re-checked against the
    # grant and scope rules already loaded above. The probe layer must not have
    # to fetch rules itself, and must not be trusted to ask.
    authorization_context_var.set(context)
    # Published for the probe tools: a redirect hop has to clear the same gate as
    # the original request, and the probe layer has no grant of its own to check
    # it against. Module-level, since the probes are dispatched through FastMCP's
    # own schema and cannot take a trusted argument for it.
    http_probe_server_module.set_redirect_guard(context)


# Prefixes a probe tool raises for a request it refuses to send. These are
# argument errors, not sandbox failures: an unknown identity or an out-of-range
# count means the caller must fix the request, and reporting it as a 500 would
# read as an outage and invite pointless retries.
_REJECTED_ARGUMENT_PREFIXES = (
    "unknown identity",
    "unknown baseline identity",
    "duplicate identity label",
    "identity labels must be",
    "at least one variant",
    "at most",
    "count must be",
    "at least 2",
    "interval must be",
    "variants per comparison",
    "comparison exceeds",
    "insufficient",
    "exceeds the permitted",
    "unsupported method",
    "scheme",
    "no host",
    "invalid url",
    # A smuggling variant outside the two fixed ones, and a credential passed
    # through the WebSocket header bag instead of a declared identity, are both
    # the caller asking for something the tool will not do.
    "smuggle_variant",
    "variant must be",
    # Refusals from a tool's own header validation all read "Header 'X' <reason>",
    # so the classifier matches the reason rather than the header name, which
    # keeps working for smuggling's framing names and the WebSocket credential
    # rule alike.
    "carries a credential",
)

# Substrings that identify a refusal wherever they appear in the message. A
# tool's own wording is its own; pinning whole prefixes here means adding a
# refusal has to edit two files in two services or it silently becomes a 500.
_REJECTED_ARGUMENT_MARKERS = (
    "carries a credential",
    "cannot be set",
    "must be an object of name/value strings",
    "header names and values must be strings",
    "header names must be single-line",
    "header values must not contain newlines",
)


def _is_rejected_argument(detail: str) -> bool:
    """True when a tool's error means 'this request was refused', not 'it broke'.

    FastMCP prefixes the tool's own message with "Error executing tool <name>:",
    so a prefix match against the raw string would miss every case.
    """
    text = (detail or "").lower()
    message = text
    # The prefix is added once per MCP hop, so an outer tool re-reporting an
    # inner tool's error stacks it. Strip every layer before matching.
    while True:
        _, marker, after = message.partition("error executing tool")
        if not marker:
            break
        _, _, after = after.partition(":")
        message = after.strip()
    return (
        any(message.startswith(p) for p in _REJECTED_ARGUMENT_PREFIXES)
        or any(marker in message for marker in _REJECTED_ARGUMENT_MARKERS)
    )


def get_caller() -> Optional[str]:
    try:
        ctx = mcp.get_context()
        if ctx and ctx._request_context:
            request = ctx.request_context.request
            if request and hasattr(request, "headers"):
                val = request.headers.get("X-Wraith-Caller")
                if val:
                    return val
    except Exception:
        pass
    return caller_context.get()

def unwrap_inner(result):
    """The per-tool servers' call_tool returns a (content_blocks, structured)
    tuple. Returning that tuple from an outer @mcp.tool() makes FastMCP encode
    it twice, so the agent sees duplicated JSON. Return just the structured
    payload so it is serialized exactly once (JSON blocks), never the tuple."""
    if isinstance(result, tuple) and len(result) == 2:
        structured = result[1]
        if isinstance(structured, (dict, list, BaseModel)):
            return structured
        return result[0]
    return result

# Initialize tool providers
nmap = NmapServer()
nuclei = NucleiServer()
sqlmap = SQLMapServer()
hydra = HydraServer()
metasploit = MetasploitServer()
web_tools = WebToolsServer()
zap = ZapServer()
http_probe_server = HttpProbeServer()

# Register tools from each provider to the main mcp instance
@mcp.tool()
async def run_nmap_scan(target: str, ports: str = "1-1000", scan_type: str = "-sV"):
    caller = get_caller()
    return unwrap_inner(await nmap.mcp.call_tool("run_nmap_scan", {"target": target, "ports": ports, "scan_type": scan_type, "caller": caller}))

@mcp.tool()
async def run_nuclei_scan(target: str, category: str = "default"):
    caller = get_caller()
    return unwrap_inner(await nuclei.mcp.call_tool("run_nuclei_scan", {"target": target, "category": category, "caller": caller}))

@mcp.tool()
async def run_sqlmap(url: str, param: str = None, method: str = "GET", data: str = None):
    caller = get_caller()
    return unwrap_inner(await sqlmap.mcp.call_tool("run_sqlmap", {"url": url, "param": param, "method": method, "data": data, "caller": caller}))

@mcp.tool()
async def run_arjun(url: str):
    """Discover URL/body parameters with Arjun (gated on scope + signed grant)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_arjun", {"url": url, "caller": caller}))

@mcp.tool()
async def run_dalfox(url: str):
    """Scan a URL for XSS with Dalfox (gated on scope + signed grant)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_dalfox", {"url": url, "caller": caller}))

@mcp.tool()
async def run_corsy(url: str):
    """Check a target's CORS policy with Corsy (gated on scope + signed grant)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_corsy", {"url": url, "caller": caller}))

@mcp.tool()
async def run_commix(url: str, param: str = None, method: str = "GET", data: str = None):
    """Test a URL/parameter for OS command injection with Commix (gated)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_commix", {"url": url, "param": param, "method": method, "data": data, "caller": caller}))

@mcp.tool()
async def run_ghauri(url: str, param: str = None, method: str = "GET", data: str = None):
    """Test a URL/parameter for SQL injection with Ghauri (gated)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_ghauri", {"url": url, "param": param, "method": method, "data": data, "caller": caller}))

@mcp.tool()
async def run_jwt_tool(token: str, target: str, mode: str = "alg", pubkey: str = None):
    """Decode a JWT and test its algorithm handling against `target` (gated)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_jwt_tool", {"token": token, "target": target, "mode": mode, "pubkey": pubkey, "caller": caller}))

@mcp.tool()
async def run_nikto(url: str):
    """Web server scan with Nikto (gated on scope + signed grant)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_nikto", {"url": url, "caller": caller}))

@mcp.tool()
async def run_xsstrike(url: str, data: str = None):
    """Test a URL for reflected XSS with XSStrike (gated on scope + signed grant)."""
    caller = get_caller()
    return unwrap_inner(await web_tools.mcp.call_tool("run_xsstrike", {"url": url, "data": data, "caller": caller}))

@mcp.tool()
async def run_zap_baseline(url: str):
    """Spider a URL and collect ZAP passive findings (gated on scope + grant)."""
    caller = get_caller()
    return unwrap_inner(await zap.mcp.call_tool("run_zap_baseline", {"url": url, "caller": caller}))

@mcp.tool()
async def run_zap_active(url: str):
    """Run ZAP's active scanner (gated; requires aggressive authorization)."""
    caller = get_caller()
    return unwrap_inner(await zap.mcp.call_tool("run_zap_active", {"url": url, "caller": caller}))

@mcp.tool()
async def run_hydra(target: str, service: str, user: str, pass_list: str):
    caller = get_caller()
    verify_caller("run_hydra", caller)
    return unwrap_inner(await hydra.mcp.call_tool("run_hydra", {"target": target, "service": service, "user": user, "pass_list": pass_list, "caller": caller}))

@mcp.tool()
async def list_msf_modules(search: str):
    caller = get_caller()
    return unwrap_inner(await metasploit.mcp.call_tool("list_modules", {"search": search, "caller": caller}))

@mcp.tool()
async def run_msf_module(module: str, target: str, options: dict):
    caller = get_caller()
    verify_caller("run_msf_module", caller)
    return unwrap_inner(await metasploit.mcp.call_tool("run_module", {"module": module, "target": target, "options": options, "caller": caller}))

@mcp.tool()
async def http_probe(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
):
    """Send one agent-authored HTTP request and capture the full raw response.

    This is the validation primitive: craft the exact request a hypothesis
    predicts, execute it, and inspect what actually came back. Safety gates
    (scope, killswitch, rate limit) are enforced by the caller in
    active_exploit_runner before this tool is ever reached.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects, "caller": caller,
    }))

@mcp.tool()
async def http_probe_diff(
    url: str,
    variants: List[dict],
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    identities: Optional[List[dict]] = None,
    baseline_identity: Optional[str] = None,
):
    """Send a request, re-send it with deliberate changes, and diff the responses.

    This is how bugs that only exist as a *difference* get evidence: broken
    object-level authorization, input handling, error-based disclosure. Each
    variant must target the same host/port/scheme as the baseline, and a
    difference is only material if it survives normalization of expected
    volatile fields.

    Pass test accounts as named `identities` and reference them by label from a
    variant to compare what two principals can see. Credential values are used
    to send the request and then withheld from the returned evidence. Use only
    accounts you own or are authorized to test with. Safety gates (scope,
    killswitch, rate limit) are enforced by active_exploit_runner before this
    tool is reached.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_diff", {
        "url": url, "variants": variants, "method": method, "headers": headers,
        "body": body, "timeout": timeout, "follow_redirects": follow_redirects,
        "identities": identities, "baseline_identity": baseline_identity,
        "caller": caller,
    }))

@mcp.tool()
async def http_probe_race(
    url: str,
    method: str = "POST",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    count: int = 3,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Send one request several times concurrently and return every capture.

    For single-use actions (coupon redemption, account creation, checkout, vote)
    the observable question is whether the endpoint serializes the operation:
    if more than one of several simultaneous identical requests succeeds, the
    action is not serialized. The concurrent count is small and bounded on
    purpose — this is a missing-lock check, not a stress tool. Safety gates
    (scope, killswitch, rate limit) are enforced by active_exploit_runner before
    this tool is reached.

    Declare ``identities`` and name one in ``identity`` to run the whole burst as
    a single authenticated user, which is the meaningful test for a one-shot
    capability. The session token is withheld from the returned evidence.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_race", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects,
        "count": count, "identities": identities, "identity": identity,
        "caller": caller,
    }))

@mcp.tool()
async def http_probe_timing(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    repeats: int = 3,
    interval: float = 0.0,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Send one request repeatedly and return median elapsed_ms."""
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_timing", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects, "repeats": repeats,
        "interval": interval, "identities": identities, "identity": identity,
        "caller": caller,
    }))


@mcp.tool()
async def http_probe_threshold(
    url: str,
    method: str = "GET",
    headers: Optional[dict] = None,
    body=None,
    timeout: float = 20.0,
    follow_redirects: bool = False,
    count: int = 10,
    interval: float = 0.25,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Send one request repeatedly in sequence to observe where throttling starts.

    For a missing rate limit on login, password reset or any expensive endpoint.
    Absence of a limit is only observable by exceeding one, so this repeats the
    request and reports the index of the first refusal; a zero means no throttle
    was seen within the tested range. Requests are sequential deliberately — a
    rate limiter counts arrivals over a window, so a burst would measure
    concurrency instead. Count is bounded; this measures a budget rather than
    loading a host. Safety gates are enforced by active_exploit_runner first.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_threshold", {
        "url": url, "method": method, "headers": headers, "body": body,
        "timeout": timeout, "follow_redirects": follow_redirects,
        "count": count, "interval": interval,
        "identities": identities, "identity": identity, "caller": caller,
    }))

@mcp.tool()
async def http_probe_smuggle(
    url: str,
    variant: str = "both",
    method: str = "POST",
    headers: Optional[dict] = None,
    timeout: float = 20.0,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Test whether a proxy chain disagrees about where a request ends.

    A front-end that trusts Content-Length and a back-end that trusts
    Transfer-Encoding read different numbers of bytes out of the same request,
    and the difference becomes the start of the next request the back-end serves.
    That is request smuggling: a smuggled request stealing another user's session
    or poisoning a cache.

    Sends one ambiguous request and one confirmation per variant on a single
    connection and compares the answers to the requests. If the target replies
    more times than it was asked, or answers the generated hidden request in
    place of the caller's, it parsed one request as two.

    Bounded hard, because this is the one tool here that can send a request the
    caller did not write: the URL and variant name are yours, the hidden request
    is generated against the target's own authority, and it cannot be pointed at a
    third party. Grading target is ``desync_detected``.

    Expect hardened stacks to reject the malformed framing outright; that is a
    clean negative, not an error. Test only what you are authorized to test.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_smuggle", {
        "url": url, "variant": variant, "method": method, "headers": headers,
        "timeout": timeout, "identities": identities, "identity": identity,
        "caller": caller,
    }))

@mcp.tool()
async def http_probe_websocket_auth(
    url: str,
    headers: Optional[dict] = None,
    message: str = "ping",
    timeout: float = 10.0,
    identities: Optional[list] = None,
    identity: Optional[str] = None,
):
    """Open a WebSocket as an anonymous visitor and see whether that is allowed.

    A WebSocket handshake is an ordinary HTTP GET, so a browser will send one
    cross-origin with the victim's cookies attached and never prompt the user
    about it. The question that matters is therefore not whether the socket is
    encrypted but who is allowed to open one.

    Completes a real RFC 6455 handshake with no credentials, verifies the server
    echoed a correct Sec-WebSocket-Accept, then reads a few frames before sending
    anything. A server that answers 101 and immediately starts pushing has handed
    a live data stream to whoever asked.

    Grade against ``findings``: ``unauthenticated_upgrade_granted``,
    ``data_served_before_any_client_message``,
    ``sec_websocket_accept_missing_or_invalid``, or ``upgrade_rejected`` for a
    refusal. Pass ``identities`` plus ``identity`` to repeat the upgrade as a
    known user and compare. One handshake and a handful of frames; the handshake
    headers are generated here rather than accepted from the caller.
    """
    caller = get_caller()
    return unwrap_inner(await http_probe_server.mcp.call_tool("http_probe_websocket_auth", {
        "url": url, "headers": headers, "message": message, "timeout": timeout,
        "identities": identities, "identity": identity, "caller": caller,
    }))

# The gate has to be on the path into a tool, not on one of the paths to it.
#
# It used to be called only by the REST bridge below, and that left the same
# tools reachable with no grant at all over the transports the bridge does not
# sit in front of. `mcp.run(transport="sse")` publishes the identical tool set
# through the same object, and FastMCP dispatches straight to the tool
# function, so opening a different transport was enough to walk past the gate.
# `X-Wraith-Caller` does not close that: it is a header the caller sets itself.
#
# `mcp._tool_manager.call_tool` is the one point every transport passes through,
# so wrapping it covers SSE, streamable HTTP, the bridge, and any transport
# added later. Wrapping `mcp.call_tool` instead would be inert: FastMCP binds
# `self.call_tool` into the low-level request handlers inside `__init__`, which
# has already run by the time anything here could be substituted.
_gate_done: ContextVar[bool] = ContextVar("gate_done", default=False)


def _enforce_gate(tool_name: str, body: dict) -> None:
    """Gate a traffic-sending tool unless this call has already been gated.

    A grant is single use, so the gate must not be consulted twice for one
    dispatch: the bridge gates, then calls `mcp.call_tool`, which arrives back
    here. The bridge records that it already gated and this returns without
    touching the nonce, so a valid grant still buys exactly one call.
    """
    if tool_name not in GATED_NETWORK_TOOLS or _gate_done.get():
        return
    gate_request(tool_name, body)


def _install_gate_interceptor() -> None:
    manager = mcp._tool_manager
    dispatch = manager.call_tool

    async def gated_call_tool(name, arguments, context=None, convert_result=False):
        try:
            _enforce_gate(name, arguments or {})
        except HTTPException as exc:
            # A transport that is not the bridge has no HTTP status of its own
            # to refuse with, and the client is waiting on an MCP result rather
            # than a response, so the refusal is reported as the tool error an
            # MCP client knows how to read, carrying the same reason. The bridge
            # never reaches this: it gates first and marks the call as gated, so
            # it keeps answering 403 with `{"error": ...}` itself.
            raise ToolError(exc.detail) from None
        return await dispatch(name, arguments, context=context, convert_result=convert_result)

    manager.call_tool = gated_call_tool


_install_gate_interceptor()

# Add internal REST bridge for Phase 5 executor
@mcp.custom_route("/tools/{tool_name}/call", methods=["POST"])
async def call_tool_internal(request):
    # FastMCP custom_route passes the Starlette request object
    body = await request.json()
    tool_name = request.path_params["tool_name"]

    caller = request.headers.get("X-Wraith-Caller")
    verify_caller(tool_name, caller)

    # Set context for the duration of this call so @mcp.tool() wrappers can see it
    try:
        gate_request(tool_name, body, request=request)
    except HTTPException as exc:
        return JSONResponse(content={"error": exc.detail, "success": False},
                            status_code=exc.status_code)

    # This call is already gated, and the grant it spent is single use. The
    # interceptor every transport shares will see this and not gate again.
    gated = _gate_done.set(True)
    token = caller_context.set(caller)
    grant_token = grant_context.set(request.headers.get("X-Wraith-Grant"))

    # FastMCP stores tool handlers in a dictionary
    # For simplicity, we just use call_tool which is an internal method
    # It returns [TextContent, ...]
    try:
        result = await mcp.call_tool(tool_name, body)
    except Exception as e:
        # A rejected argument (unknown identity, count out of range) is the
        # caller's mistake, not a sandbox failure, so it is reported as a 400
        # with the reason rather than a 500. FastMCP wraps a tool's own
        # exception in ToolError, so the rejected-argument signal has to be
        # recovered from the message.
        detail = str(e)
        if _is_rejected_argument(detail):
            return JSONResponse(content={"error": detail, "success": False},
                                status_code=400)
        return JSONResponse(content={"error": detail, "success": False}, status_code=500)
    finally:
        caller_context.reset(token)
        grant_context.reset(grant_token)
        _gate_done.reset(gated)

    # Since call_tool returns a list of Content objects, we need to serialize them
    return JSONResponse(content=jsonable_encoder(result))

# Lightweight health check endpoint for Docker healthcheck (avoids relying
# on the SSE stream endpoint, which never "completes" a normal HTTP request)
@mcp.custom_route("/health", methods=["GET"])
async def health_check(request):
    return JSONResponse(content={"status": "healthy"})

if __name__ == "__main__":
    # Before serving, not lazily: with no gate secret every tool call is refused
    # anyway, so booting and answering 403s just disguises a missing secret as a
    # target problem.
    validate_startup_secrets()
    mcp.run(transport="sse")
