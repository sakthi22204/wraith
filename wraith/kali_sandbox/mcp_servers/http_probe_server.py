"""http_probe: send one agent-authored HTTP request and capture the full response.

This is the primitive that makes genuine validation possible. Every other tool in
this sandbox is a fixed-purpose scanner, so the agent can only ever restate
"run nuclei again". With http_probe the agent writes a request itself, executes
it, and reads the actual response. That captured exchange is simultaneously:

  * the proof-of-concept,
  * the validation evidence,
  * and the reproduction recipe (it is literally the traffic that was sent).

The probe is deliberately narrow. It is an HTTP client for a single authorized
target, not a pivoting primitive: no arbitrary socket control, no cross-host
redirection following, and a hard cap on response bytes so a hostile target
cannot exhaust memory.

The one deliberate exception is :meth:`HttpProbeServer.smuggle`, which needs raw
socket control to send framing a normal HTTP client refuses to produce. It is
bounded hard and generates its own smuggled request against the target's own
authority -- see ``SMUGGLE_VARIANTS`` above for why the caller is not allowed to
supply that request.
"""
import asyncio
import base64
import hashlib
import json
import re
import secrets
import ssl
import time
from contextvars import ContextVar
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import httpx
from pydantic import BaseModel, Field

from .common.base_server import BaseSecurityServer
from .common.redaction import (
    extract_session_token, redact_capture, redact_headers, redact_text,
)
from .gate import GateError, revalidate_hop

# The gate's context for the request in flight, published by main.gate_request.
# This is a ContextVar rather than a tool argument on purpose: the probe tools
# are reachable through FastMCP's own schema, so a `redirect_guard` parameter
# would be a caller-supplied guard -- something that could wave a hop through
# unchecked. Set by the gate, read by the probe, never written by a request.
_redirect_guard: ContextVar = ContextVar("wraith_redirect_guard", default=None)


def set_redirect_guard(context) -> None:
    """Publish the verified gate context for the request being dispatched."""
    _redirect_guard.set(context)
from .common.response_diff import classify_differential, summarize_differential

# Guards against a hostile or broken target exhausting the sandbox.
MAX_RESPONSE_BYTES = 512 * 1024
MAX_REQUEST_BODY = 256 * 1024
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Default browser-like UA when the caller does not supply one. Many real-world
# WAFs (Akamai, Cloudflare, ...) %403%-drop UA-less or httpx-default UAs, which
# would turn every probe into an unresolvable "connection" result. A standard
# browser string is benign and keeps the probe reading like ordinary traffic.
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

# A differential test costs two requests. This bounds the whole comparison so a
# caller cannot turn a single probe into an unbounded sweep. The per-variant cap
# allows a UNION column-count sweep (one variant per candidate width); it is
# still a fixed ceiling, and the comparison-level cap scales with it.
MAX_COMPARISON_REQUESTS = 2
MAX_VARIANTS = 12

# A race sweep sends the *same* request several times at once. The cap is
# deliberately small: concurrency multiplies load on a live host, so the harness
# is a check for a missing lock, not a stress tool.
MAX_RACE_REQUESTS = 6

# A threshold sweep sends the same request repeatedly in quick succession to find
# where a target starts refusing traffic. Higher than the race cap because the
# requests are sequential and a budget is typically well above the concurrency
# needed to break a lock. 50 is enough to show a login has no per-account
# throttle at all (a spray needs breadth, not volume); it is still a fixed
# ceiling, not a load tool.
MAX_THRESHOLD_REQUESTS = 50
# Timing harness: repeat the same request N times and compute median elapsed_ms
# (matches the "3-repetition timing delta" requirement). Bounded like other
# sweeps; not a stress test.
MAX_TIMING_REPEATS = 10
MIN_TIMING_REPEATS = 2

# Statuses that mean "you are going too fast", plus the ones targets use when
# shedding load. A target answering 503 or 402 to a burst is not necessarily
# rate limiting, so the full observed statuses travel with the verdict.
THROTTLE_STATUSES = frozenset({429, 503})

# Pause between threshold requests. Long enough to read as sequential traffic
# rather than a burst, short enough to stay inside a typical one-minute window.
THRESHOLD_INTERVAL = 0.25

# --- Request smuggling -------------------------------------------------------
#
# Smuggling works by sending one request that a front-end and a back-end parse
# into two different requests. That makes it the one harness here that can send
# a request the caller did not write, so its limits are structural rather than
# advisory:
#
#   * The caller never supplies the smuggled bytes. It supplies a URL and a
#     variant name; this tool generates the hidden request itself, from the
#     same authority as the request it is hiding in. Accepting caller-authored
#     smuggled bytes would turn the sandbox into an open request-desync
#     primitive aimed at whatever the operator happened to point it at.
#   * The hidden request's Host is always the target authority, so a desync
#     cannot be aimed at a third party. The worst outcome is confused framing
#     against the host under test.
#   * Bounded: two variants, two requests each, one connection each.
#
# Only these two classic ambiguity pairs are offered. There is no "raw bytes"
# mode and no way to smuggle towards an arbitrary destination.
MAX_SMUGGLE_VARIANTS = 2
SMUGGLE_VARIANTS = ("cl_te", "te_cl")

# Requests the tool writes per variant: the ambiguous one, then a confirmation.
# The confirmation is what makes a desync observable -- if the target split one
# request into two, the response to the request we did *not* send comes back
# first.
SMUGGLE_REQUESTS_SENT_PER_VARIANT = 2

# Requests the *target* receives per variant when the attempt desyncs: the two
# above plus the hidden one. Budgeting has to count this, not just what we
# write, because a rate limiter and an operator's log both see three.
SMUGGLE_REQUESTS_RECEIVED_PER_VARIANT = 3

# Appended to the caller's path to form the hidden request's target. Any real
# application 404s an unrecognised path, which is what gives the confirmation
# response a status the hidden request can be told apart by.
SMUGGLE_CANARY_SUFFIX = "wraith-smuggle-canary"

# Status a target returns for the canary path. Detection compares the *order*
# of statuses rather than trusting a header the target chooses to echo, so a
# hostile or minimal target cannot influence the verdict.
SMUGGLE_NOT_FOUND = 404

# How long to keep listening *after* the expected number of responses has arrived.
# A desync shows up as one response more than was sent, and that response is
# produced a moment after the ones we did ask for -- so the read has to outlive
# the expected count, or the one answer that proves the vulnerability is the one
# we stop reading before. Bounded so a target that never closes cannot hold the
# tool open.
SMUGGLE_DESYNC_GRACE_SECONDS = 2.0

# Hard cap on the generated exchange, so a pathological target cannot make the
# tool buffer without bound.
MAX_SMUGGLE_RESPONSE_BYTES = 256 * 1024
SMUGGLE_TIMEOUT_CEILING = 30.0

# --- WebSocket upgrade authentication ---------------------------------------
#
# A WebSocket handshake is a plain HTTP GET, which means the usual browser
# protections do not automatically apply: the browser will happily send a
# cross-origin upgrade with the victim's cookies attached, and unlike a normal
# request there is no "is this a navigation the user intended" check. So the
# question worth asking is not "is the socket encrypted" but "who is allowed to
# open one, and does the server notice when nobody is".
#
# The client is hand-rolled rather than pulled in as a dependency because the
# surface needed is one handshake, one masked frame, and a bounded read. That is
# small enough that a library would add more bytes to audit than it saves.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
WS_VERSION = "13"

# One handshake, one client frame, a handful of frames read back. Bounded because
# a server that pushes an unbounded stream would otherwise let a probe sit there
# reading forever.
WS_MAX_FRAMES_READ = 4
WS_MAX_FRAME_BYTES = 8 * 1024
WS_MAX_SEND_BYTES = 1024
WS_TIMEOUT_CEILING = 30.0

# Findings are fixed strings so a runner can grade them without interpreting
# prose.
WS_FINDING_UNAUTHENTICATED_UPGRADE = "unauthenticated_upgrade_granted"
WS_FINDING_DATA_BEFORE_AUTH = "data_served_before_any_client_message"
WS_FINDING_ACCEPT_NOT_VALIDATED = "sec_websocket_accept_missing_or_invalid"
WS_FINDING_UPGRADE_REJECTED = "upgrade_rejected"

# Header names a caller may not set: they would let a probe authenticate as
# someone else or smuggle a second request stream.
BLOCKED_REQUEST_HEADERS = frozenset({
    "content-length", "connection", "transfer-encoding",
    "upgrade", "proxy-authorization", "te", "trailer",
})
# ``host`` is deliberately settable: it only changes the Host line sent to the
# destination already resolved from the URL, so routing and scope are unaffected
# while Host-header/cache-poisoning hypotheses become testable.

# Every framing and routing header is the tool's to write. The harness needs to
# send Content-Length and Transfer-Encoding, but the *caller* must not: letting
# them through would append a second, conflicting framing header to the ambiguous
# request, and the resulting byte stream would test nothing in particular. The
# ambiguity being tested is a specific one, and a caller-chosen length would
# change it out from under the verdict.
#
# ``host`` is here for a second reason: the hidden request's Host is what keeps a
# desync pointed at the target under test rather than a third party, and the
# tool always writes the target authority itself.
BLOCKED_SMUGGLE_HEADERS = frozenset({
    "host", "content-length", "transfer-encoding", "connection", "keep-alive",
    "proxy-connection", "upgrade", "proxy-authorization", "te", "trailer",
    "content-encoding", "expect",
})

# The WebSocket handshake is generated here, so every header that defines it is
# not settable: letting a caller supply Upgrade or Sec-WebSocket-Key would only
# let it produce a request that is not a WebSocket handshake at all.
# ``Sec-WebSocket-Protocol`` is deliberately absent from this set -- it is how a
# server advertises and selects an authenticated subprotocol, so a caller needs
# to be able to ask for one.
BLOCKED_WEBSOCKET_HEADERS = frozenset({
    "host", "connection", "upgrade", "content-length", "transfer-encoding",
    "sec-websocket-key", "sec-websocket-version", "sec-websocket-accept",
    "sec-websocket-extensions", "proxy-authorization", "te", "trailer",
    "keep-alive", "proxy-connection", "expect",
})

# The whole question this tool answers is whether the endpoint checks who is
# opening the socket, so a credential cannot be smuggled in through the generic
# header bag: ``Authorization``/``Cookie`` here would be sent while the record
# still claimed the run was anonymous, turning a safe endpoint into a reported
# finding. Credentials belong in ``identities``, which labels the run honestly.
BLOCKED_WEBSOCKET_AUTH_HEADERS = frozenset({
    "authorization", "cookie", "proxy-authorization", "x-api-key",
})


class ProbeCapture(BaseModel):
    """A single executed request and everything observed about the response."""

    request_url: str = ""
    request_method: str = "GET"
    request_headers: Dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = None

    status_code: Optional[int] = None
    reason_phrase: str = ""
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    response_size_bytes: int = 0
    body_truncated: bool = False

    elapsed_ms: Optional[float] = None
    final_url: str = ""
    redirects: List[str] = Field(default_factory=list)

    # Observable request/response facts the agent can assert against, so it does
    # not have to regex a whole HTML page to answer a yes/no question.
    content_type: str = ""
    server_header: str = ""
    body_sha256: str = ""

    error: Optional[str] = None
    reached_target: bool = False

    # Transient: a credential recovered from a successful login response, and
    # only when the caller explicitly asked for it (the single-probe tool). It
    # is never part of the redacted evidence; it exists so a confirmed bypass
    # can become an identity for a follow-up authenticated replay.
    auth_token: Optional[str] = None


class Identity(BaseModel):
    """A named set of credentials used to act as a particular user.

    Identities exist so that authorization testing never has to inline a real
    session token into a request that will be captured as evidence. The label
    travels into the record; the credential values are used to send the request
    and then dropped.
    """

    label: str
    headers: Dict[str, str] = Field(default_factory=dict)
    description: str = ""


class ProbeVariant(BaseModel):
    """One way of perturbing the baseline request.

    Only the fields that differ need to be set; anything omitted is inherited
    from the baseline. That keeps a mutation readable as an actual hypothesis
    ("same request, but with a single quote in the id") instead of a full
    re-specification that can drift from what was really compared.
    """

    label: str = ""
    url: Optional[str] = None
    method: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    timeout: Optional[float] = None
    identity: Optional[str] = None


class VariantResult(BaseModel):
    """A variant's own capture plus its difference from the baseline."""

    label: str
    capture: Dict[str, Any] = Field(default_factory=dict)
    difference: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""
    identity: str = ""
    authz_signal: Optional[str] = None


class ProbeRace(BaseModel):
    """The same request sent concurrently ``count`` times.

    A single-use action (coupon redemption, account creation, checkout, vote)
    should honour only one of a set of simultaneous requests. When several
    succeed, the endpoint is not serializing the operation and a caller can
    reuse a one-shot capability. ``captures`` is kept in full so the count is
    reviewable from the evidence rather than taken on trust.
    """

    requested_url: str = ""
    method: str = "GET"
    captures: List[Dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    total_requests: int = 0
    identity: str = ""
    identities_used: List[str] = Field(default_factory=list)


class ProbeThreshold(BaseModel):
    """One request sent ``count`` times in quick succession to observe throttling.

    A missing rate limit is only observable by sending more requests than a
    well-behaved target would accept and seeing that none were refused. This is
    the mirror image of a race sweep: the requests are *not* concurrent, because
    a rate limiter counts request arrivals over a window and concurrency would
    measure a different property.

    ``throttled_at`` is the 1-based index of the first refused request, or 0 if
    none was. That is the field to grade against: it is the observed budget, and
    ``statuses`` is kept in full so the count is reviewable from the evidence
    rather than taken on trust.
    """

    requested_url: str = ""
    method: str = "GET"
    captures: List[Dict[str, Any]] = Field(default_factory=list)
    count: int = 0
    total_requests: int = 0
    throttled_at: int = 0
    throttled_count: int = 0
    throttle_statuses: List[int] = Field(default_factory=list)
    rate_limited: bool = False
    identity: str = ""
    identities_used: List[str] = Field(default_factory=list)


class ProbeTiming(BaseModel):
    """One request sent ``repeats`` times to obtain timing samples.

    Returns median elapsed_ms across successful reaches; captures preserved for
    audit. This is intentionally signature-only for B0: the expectation grammar
    (``response time >= N ms``) already decides using ``elapsed_ms``.
    """

    requested_url: str = ""
    method: str = "GET"
    captures: List[Dict[str, Any]] = Field(default_factory=dict)
    repeats: int = 0
    total_requests: int = 0
    reached_count: int = 0
    elapsed_ms_samples: List[float] = Field(default_factory=list)
    median_elapsed_ms: Optional[float] = None
    identity: str = ""
    identities_used: List[str] = Field(default_factory=list)


class SmuggleAttempt(BaseModel):
    """One ambiguity pair, and what the target did with it."""

    variant: str = ""
    #: The hidden request's path. Generated, not supplied by the caller.
    canary_path: str = ""
    #: Exactly what went on the wire, minus any identity credentials. Kept so a
    #: reviewer can reproduce the finding byte for byte, which is the whole
    #: point of a smuggling capture.
    sent_preview: str = ""
    #: Final (non-1xx) statuses in the order they came back.
    statuses: List[int] = Field(default_factory=list)
    requests_sent: int = 0
    responses_received: int = 0
    #: A 404 arrived that the caller's own path would not produce, i.e. the
    #: hidden request was really served. Corroborating detail, not the verdict:
    #: it is only meaningful because the confirmation's own status is known.
    canary_served: bool = False
    #: True when the target returned more answers than it was sent requests, or
    #: answered the hidden request in place of ours. Either means it parsed one
    #: request as two. See :meth:`HttpProbeServer.smuggle`.
    split_detected: bool = False
    note: str = ""


class ProbeSmuggle(BaseModel):
    """Result of probing for HTTP request smuggling over a raw socket.

    ``desync_detected`` is the field to grade against. It is set only when the
    target's answers outnumber the requests it was sent, or when the hidden
    request was answered in place of the caller's -- either way it parsed one
    request as two. ``attempts`` carries the statuses behind that conclusion so
    it can be re-read rather than trusted.

    Both variants are always reported, including the ones that did not split.
    A front-end that disagrees only about the reverse pair is a real finding
    about a partially-hardened setup, so negative results are evidence too.
    """

    requested_url: str = ""
    method: str = "POST"
    authority: str = ""
    variants_tried: List[str] = Field(default_factory=list)
    attempts: List[SmuggleAttempt] = Field(default_factory=list)
    desync_detected: bool = False
    total_requests: int = 0
    identity: str = ""
    identities_used: List[str] = Field(default_factory=list)


class WebSocketFrame(BaseModel):
    """One decoded frame from the server, with its payload preview."""

    opcode: int = 0
    payload_preview: str = ""
    payload_bytes: int = 0
    truncated: bool = False


class ProbeWebSocketAuth(BaseModel):
    """Whether a WebSocket endpoint authenticates the upgrade, and what it leaks.

    The WebSocket handshake is a plain HTTP GET, so a browser will send a
    cross-origin one with the victim's cookies attached and there is no
    navigation prompt to stop it. What matters is therefore not whether the
    socket is encrypted but whether the server checks who is opening it, and
    whether it starts pushing data to a socket that presented no credentials.

    ``findings`` holds fixed strings rather than prose so a runner can grade the
    result without interpreting English. The ones that matter:

      * ``unauthenticated_upgrade_granted`` -- the server completed a 101 with no
        credentials of any kind sent.
      * ``data_served_before_any_client_message`` -- it then started pushing,
        which is what turns an open upgrade into a data leak rather than a
        curiosity.
      * ``sec_websocket_accept_missing_or_invalid`` -- the handshake response did
        not prove it was addressed to *this* request, which is the check that
        stops a malicious page from reading a cross-origin socket.

    ``upgrade_granted`` and ``accept_valid`` are kept separate on purpose: a
    101 with a bad accept header is a different, subtler problem from a 101 that
    was never meant to be reachable without a session.
    """

    requested_url: str = ""
    authority: str = ""
    handshake_status: int = 0
    upgrade_granted: bool = False
    accept_valid: bool = False
    frames: List[WebSocketFrame] = Field(default_factory=list)
    data_before_client_message: bool = False
    findings: List[str] = Field(default_factory=list)
    note: str = ""
    identity: str = ""
    identities_used: List[str] = Field(default_factory=list)


class ProbeComparison(BaseModel):
    """Baseline response compared against one or more perturbed requests.

    ``any_material`` is the field to branch on: it is true only when at least
    one variant produced a change that survived volatile-field normalization,
    which is the precondition for treating a difference as evidence.

    ``blocked`` means the comparison could not reach the application at all
    (a redirect baseline, or an edge defense that rejected the payload). That
    is neither a finding nor a clean result, and ``inconclusive`` is set so
    callers report "could not test" rather than "nothing found".
    """

    baseline: Dict[str, Any] = Field(default_factory=dict)
    variants: List[VariantResult] = Field(default_factory=list)
    any_material: bool = False
    material_signals: List[str] = Field(default_factory=list)
    blocked: bool = False
    blocked_reasons: List[str] = Field(default_factory=list)
    inconclusive: bool = False
    authz_findings: List[str] = Field(default_factory=list)
    identities_used: List[str] = Field(default_factory=list)
    total_requests: int = 0


# An authorization problem is a *cross-identity* problem: the same URL answering
# one identity with data the other identity is entitled to. Comparing against an
# unauthenticated baseline only shows that auth exists, which is not a bug.
def _authz_signal(
    baseline_identity: str,
    variant_identity: str,
    baseline: Dict[str, Any],
    variant: Dict[str, Any],
) -> Optional[str]:
    """Describe an authorization difference between two identities, if any."""
    if not variant_identity or variant_identity == baseline_identity:
        return None
    # With no identity on the baseline there is no second principal to compare
    # against, so any difference would be an artifact of the comparison's shape
    # rather than evidence about authorization.
    if not baseline_identity:
        return None

    base_status = baseline.get("status_code")
    var_status = variant.get("status_code")
    base_body = baseline.get("response_body") or ""
    var_body = variant.get("response_body") or ""

    if var_status == base_status and var_body == base_body:
        return (
            f"identity '{variant_identity}' received a response identical to "
            f"'{baseline_identity}' on the same URL; if these are distinct "
            f"low-privilege users, the endpoint may not be separating them"
        )

    if isinstance(base_status, int) and isinstance(var_status, int):
        if base_status >= 400 and var_status < 400:
            return (
                f"'{variant_identity}' was allowed ({var_status}) on a request where "
                f"'{baseline_identity}' was refused ({base_status}); if "
                f"'{variant_identity}' has lower privilege, this is a privilege "
                f"escalation"
            )
        if base_status < 400 and var_status < 400 and var_body != base_body:
            return (
                f"identities '{baseline_identity}' and '{variant_identity}' both "
                f"received {var_status} but different content; verify the content "
                f"is scoped to the requesting identity"
            )
    return None


def _scrub_identity_headers(capture: Dict[str, Any], identity_label: str) -> Dict[str, Any]:
    """Replace identity-sourced request headers with a label reference.

    The request has already been sent by this point, so the header values have
    served their purpose and must not travel further. Recording the label keeps
    the evidence readable ("this was sent as user_b") without storing the
    session token that made it possible.
    """
    out = dict(capture)
    headers = dict(out.get("request_headers") or {})
    if headers:
        if identity_label:
            out["request_headers"] = {"identity": identity_label, "note": "credential values withheld from evidence"}
        else:
            out["request_headers"] = {k: "[REDACTED]" for k in headers}
    out["identity"] = identity_label
    return out


def _merge_variant(baseline: Dict[str, Any], variant: ProbeVariant) -> Dict[str, Any]:
    """Resolve a variant against the baseline request it perturbs."""
    merged_headers = dict(baseline.get("headers") or {})
    if variant.headers:
        for k, v in variant.headers.items():
            if str(v).strip() == "":
                merged_headers.pop(k, None)
            else:
                merged_headers[k] = v

    merged_body = variant.body if variant.body is not None else baseline.get("body")
    return {
        "url": variant.url or baseline.get("url"),
        "method": (variant.method or baseline.get("method") or "GET").upper(),
        "headers": merged_headers,
        "body": merged_body,
        "timeout": variant.timeout if variant.timeout is not None else baseline.get("timeout", 20.0),
    }


def _coerce_text_bodies(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Re-serialize redacted bodies back to text.

    Redaction is structure-aware, so a JSON body comes back as a dict. Evidence
    has to stay a replayable text artifact that a report can render verbatim, so
    structured redacted content is re-serialized rather than dropped.
    """
    import json as _json

    out = dict(payload)
    for key in ("request_body", "response_body"):
        value = out.get(key)
        if isinstance(value, (dict, list)):
            out[key] = _json.dumps(value, indent=2, sort_keys=True)
    return out


class HttpProbeServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("HttpProbe Server")
        self.setup_tools()

    # -- validation helpers -------------------------------------------------

    def _validate_url(self, url: str) -> str:
        """Reject anything that is not a plain absolute http(s) URL."""
        if not url or not isinstance(url, str):
            raise ValueError("url is required")
        if len(url) > 4096:
            raise ValueError("url exceeds 4096 characters")

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Only http/https URLs are allowed, got '{parsed.scheme or 'none'}'")
        if not parsed.hostname:
            raise ValueError("url must include a host")

        # Reject credentials embedded in the URL; they would end up in evidence.
        if parsed.username or parsed.password:
            raise ValueError("Credentials must not be embedded in the URL")
        return url

    def _validate_method(self, method: str) -> str:
        m = (method or "GET").strip().upper()
        if m not in ALLOWED_METHODS:
            raise ValueError(f"Method '{m}' not allowed. Allowed: {sorted(ALLOWED_METHODS)}")
        return m

    def _validate_headers(
        self,
        headers: Optional[Dict[str, str]],
        blocked: frozenset = BLOCKED_REQUEST_HEADERS,
        reason: str = "is controlled by the HTTP client and cannot be set",
    ) -> Dict[str, str]:
        """Normalise caller headers, refusing the ones the tool must own.

        ``blocked``/``reason`` exist because the smuggling and WebSocket harnesses
        have a wider set than plain probing does. Checking it here rather than in
        a second pass keeps one message accurate instead of two, one of which
        would blame the HTTP client for a header the client never touches.
        """
        if not headers:
            return {}
        if not isinstance(headers, dict):
            raise ValueError("headers must be an object of name/value strings")
        if len(headers) > 50:
            raise ValueError("At most 50 headers are allowed")

        clean: Dict[str, str] = {}
        for name, value in headers.items():
            if not isinstance(name, str) or not isinstance(value, (str, int, float)):
                raise ValueError("header names and values must be strings")
            lname = name.strip().lower()
            if not lname or "\n" in name or "\r" in name:
                raise ValueError("header names must be single-line non-empty strings")
            if "\n" in str(value) or "\r" in str(value):
                raise ValueError("header values must not contain newlines")
            if lname in blocked:
                raise ValueError(f"Header '{name}' {reason}")
            clean[name] = str(value)
        return clean

    def _validate_body(self, body) -> Optional[str]:
        """Normalise a request body to the bytes that will be sent.

        Accepts a string or a JSON-ready object. The object form is what a
        caller naturally reaches for when crafting a JSON-RPC or REST request,
        and the MCP argument layer decodes a JSON-looking string back into a
        dict on the way in, so rejecting non-strings here would make every
        JSON-bodied request impossible to send.
        """
        if body is None:
            return None
        if isinstance(body, (dict, list)):
            try:
                body = json.dumps(body)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"body is not JSON-serializable: {exc}") from exc
        if not isinstance(body, str):
            raise ValueError("body must be a string or a JSON object/array")
        if len(body.encode("utf-8", errors="ignore")) > MAX_REQUEST_BODY:
            raise ValueError(f"Request body exceeds {MAX_REQUEST_BODY} bytes")
        return body

    # -- probe --------------------------------------------------------------

    MAX_REDIRECTS = 3

    async def _follow(
        self,
        client,
        resp,
        method: str,
        headers: Dict[str, str],
        body,
        *,
        redirect_guard=None,
        history: Optional[List[str]] = None,
    ):
        """Walk a redirect chain, re-checking every hop before it is requested.

        ``redirect_guard`` is the gate's context for this request. Each new URL
        has to clear it, so a 302 cannot move the request somewhere the grant
        does not cover. It is mandatory rather than optional: a caller asking to
        follow redirects without a guard would be asking for exactly the
        unchecked walk this replaces, so that is refused instead of permitted.

        A guard that raises GateError propagates, which is what stops the hop from
        being sent -- the refusal happens before the request, not after the body
        has been read and then discarded.
        """
        if history is None:
            history = []

        # Fall back to the context the gate published for this request. An
        # explicit argument wins so a caller can narrow the guard, never widen it:
        # there is no path here that skips the check when following is on.
        if redirect_guard is None:
            redirect_guard = _redirect_guard.get()

        while (
            resp.is_redirect
            and resp.status_code in (301, 302, 303, 307, 308)
            and len(history) < self.MAX_REDIRECTS
        ):
            location = resp.headers.get("location")
            if not location:
                break
            nxt = str(resp.url.join(location))

            if redirect_guard is None:
                raise GateError(
                    "following redirects requires a gate context; refusing to "
                    "follow an unchecked destination", 403,
                )
            revalidate_hop(redirect_guard, nxt)

            history.append(nxt)
            # 303, and 301/302 in practice, continue as GET without a body.
            next_method, next_body = method, body
            if resp.status_code in (301, 302, 303) and method not in ("GET", "HEAD"):
                next_method, next_body = "GET", None
            resp = await client.request(
                next_method, nxt, headers=headers, content=next_body
            )

        if resp.is_redirect and len(history) >= self.MAX_REDIRECTS:
            raise GateError(
                f"redirect chain exceeded {self.MAX_REDIRECTS} hops; refusing to "
                "follow further", 403,
            )
        return resp

    async def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
        redirect_guard=None,
        extract_token: bool = False,
    ) -> ProbeCapture:
        url = self._validate_url(url)
        method = self._validate_method(method)
        req_headers = self._validate_headers(headers)
        req_body = self._validate_body(body)

        # Inject a benign browser UA unless the caller pinned one explicitly.
        if not any(k.lower() == "user-agent" for k in (req_headers or {})):
            req_headers = dict(req_headers or {})
            req_headers["User-Agent"] = DEFAULT_USER_AGENT

        if timeout <= 0 or timeout > 120:
            raise ValueError("timeout must be between 0 and 120 seconds")

        started = time.perf_counter()
        try:
            timeout_cfg = httpx.Timeout(timeout)
            # Redirects are followed by hand rather than by httpx, so each hop
            # can be re-checked. httpx's own following walks up to three hops
            # without consulting the gate, which turns any in-scope host that
            # answers with a 302 into a way to fetch an out-of-scope one -- and
            # its body comes back as evidence.
            async with httpx.AsyncClient(
                timeout=timeout_cfg,
                follow_redirects=False,
                verify=False,
            ) as client:
                history: list[str] = []
                resp = await client.request(
                    method, url, headers=req_headers, content=req_body
                )
                if follow_redirects:
                    resp = await self._follow(
                        client, resp, method, req_headers, req_body,
                        redirect_guard=redirect_guard, history=history,
                    )
                raw = resp.content or b""
                truncated = len(raw) > MAX_RESPONSE_BYTES
                if truncated:
                    raw = raw[:MAX_RESPONSE_BYTES]

                import hashlib
                resp_headers = {k: v for k, v in resp.headers.items()}
                body_text = None
                if method != "HEAD":
                    try:
                        body_text = raw.decode(resp.encoding or "utf-8", errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        body_text = raw.decode("utf-8", errors="replace")

                capture = ProbeCapture(
                    request_url=url,
                    request_method=method,
                    request_headers=req_headers,
                    request_body=req_body,
                    status_code=resp.status_code,
                    reason_phrase=resp.reason_phrase or "",
                    response_headers=resp_headers,
                    response_body=body_text,
                    response_size_bytes=len(raw),
                    body_truncated=truncated,
                    elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                    final_url=str(resp.url),
                    redirects=list(history),
                    content_type=resp.headers.get("content-type", ""),
                    server_header=resp.headers.get("server", ""),
                    body_sha256=hashlib.sha256(raw).hexdigest(),
                    reached_target=True,
                )
        except GateError:
            # A refusal is not a probe failure and must not be dressed up as one.
            # The generic handler below turns every exception into a ProbeCapture
            # with reached_target=False, which reads to a caller as "the target was
            # unreachable" -- so a hop the gate declined would look like an
            # inconclusive result rather than a stopped request, and the analyst
            # would go looking for a network problem that does not exist.
            raise
        except httpx.TimeoutException:
            capture = ProbeCapture(
                request_url=url, request_method=method, request_headers=req_headers,
                request_body=req_body, reached_target=False,
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                error="timeout",
            )
        except httpx.ConnectError as e:
            capture = ProbeCapture(
                request_url=url, request_method=method, request_headers=req_headers,
                request_body=req_body, reached_target=False,
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                error=f"connect_error: {e}",
            )
        except Exception as e:
            capture = ProbeCapture(
                request_url=url, request_method=method, request_headers=req_headers,
                request_body=req_body, reached_target=False,
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                error=f"{type(e).__name__}: {e}",
            )

        # Redact before this leaves the sandbox: evidence must never carry
        # credentials into the graph, audit log, or a rendered report.
        raw = capture.model_dump()
        auth_token = extract_session_token(raw) if extract_token else None
        redacted = _coerce_text_bodies(redact_capture(raw))
        if auth_token:
            # Attached after redaction, so it can never appear in the evidence
            # built from the redacted capture. The runner drops it as soon as it
            # has been spent on the pivot request.
            redacted["auth_token"] = auth_token
        return ProbeCapture(**redacted)

    # -- differential comparison --------------------------------------------

    def _assert_same_origin(self, baseline_url: str, variant_url: str) -> None:
        """Refuse a variant that would send the comparison to a different host.

        A comparison is only meaningful against a controlled baseline. If a
        variant may change host, a difference could be a completely different
        service rather than any effect of the change under test, and a caller
        could use the probe to reach a host the baseline never named.
        """
        b = urlparse(self._validate_url(baseline_url))
        v = urlparse(self._validate_url(variant_url))
        if (b.hostname, b.port, b.scheme) != (v.hostname, v.port, v.scheme):
            raise ValueError(
                "Differential variants must target the same scheme/host/port as the "
                f"baseline ({b.scheme}://{b.hostname}); got {v.scheme}://{v.hostname}"
            )

    async def compare(
        self,
        url: str,
        variants: List[ProbeVariant],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
        identities: Optional[List[Identity]] = None,
        baseline_identity: Optional[str] = None,
    ) -> ProbeComparison:
        """Send a baseline request, then re-send it perturbed, and diff the results.

        This is the mode that finds bugs a single request cannot: an IDOR shows
        up as one identity receiving another's object, an injection shows up as
        a response that changes only when the payload is present, and a
        disclosure shows up as a value shape the baseline never returned.
        """
        url = self._validate_url(url)
        if not variants:
            raise ValueError("at least one variant is required for a differential comparison")
        if len(variants) > MAX_VARIANTS:
            raise ValueError(f"at most {MAX_VARIANTS} variants per comparison")

        registry, baseline_label = self._identity_registry(
            identities, baseline_identity, role="baseline identity")

        total_variants = len(variants)
        if 1 + total_variants > MAX_COMPARISON_REQUESTS * MAX_VARIANTS:
            raise ValueError("comparison exceeds the permitted request budget")

        baseline_headers = dict(headers or {})
        if baseline_label:
            baseline_headers.update(registry[baseline_label].headers)

        baseline_spec = {
            "url": url,
            "method": method,
            "headers": baseline_headers,
            "body": body,
            "timeout": timeout,
        }
        baseline = await self.probe(
            url=url, method=method, headers=baseline_headers, body=body,
            timeout=timeout, follow_redirects=follow_redirects,
        )
        baseline_dict = _scrub_identity_headers(baseline.model_dump(), baseline_label)

        results: List[VariantResult] = []
        material_signals: List[str] = []
        blocked_reasons: List[str] = []
        authz_findings: List[str] = []
        identities_used: List[str] = []
        for index, variant in enumerate(variants):
            label = variant.label or f"variant_{index + 1}"
            spec = _merge_variant(baseline_spec, variant)

            variant_identity = ""
            if variant.identity:
                if variant.identity not in registry:
                    raise ValueError(
                        f"unknown identity {variant.identity!r}; declared: "
                        f"{sorted(registry) or 'none'}"
                    )
                variant_identity = variant.identity
                # Identity headers are applied last so a variant cannot be
                # silently overridden by, or silently override, a credential.
                spec["headers"] = {**(spec.get("headers") or {}), **registry[variant_identity].headers}
                if variant_identity not in identities_used:
                    identities_used.append(variant_identity)

            self._assert_same_origin(url, spec["url"])

            variant_capture = await self.probe(
                url=spec["url"], method=spec["method"], headers=spec["headers"],
                body=spec["body"], timeout=spec["timeout"], follow_redirects=follow_redirects,
            )
            variant_dict = _scrub_identity_headers(variant_capture.model_dump(), variant_identity)
            difference = classify_differential(baseline_dict, variant_dict)
            summary = summarize_differential(difference)
            if difference.get("material"):
                material_signals.extend(f"[{label}] {s}" for s in difference.get("signals", []))
            elif difference.get("blocked"):
                blocked_reasons.extend(
                    f"[{label}] {r}" for r in (difference.get("blocked_reasons") or [])
                )

            authz = _authz_signal(baseline_label, variant_identity, baseline_dict, variant_dict)
            if authz:
                authz_findings.append(f"[{label}] {authz}")

            results.append(
                VariantResult(
                    label=label,
                    capture=variant_dict,
                    difference=difference,
                    summary=summary,
                    identity=variant_identity,
                    authz_signal=authz,
                )
            )

        return ProbeComparison(
            baseline=baseline_dict,
            variants=results,
            any_material=bool(material_signals),
            material_signals=material_signals,
            blocked=bool(blocked_reasons) and not material_signals,
            blocked_reasons=blocked_reasons,
            inconclusive=bool(blocked_reasons) and not material_signals,
            authz_findings=authz_findings,
            identities_used=identities_used,
            total_requests=1 + total_variants,
        )

    # -- race / concurrency ---------------------------------------------------

    def _validate_race_count(self, count: int) -> int:
        """A race needs at least two simultaneous requests, and never many."""
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValueError("count must be an integer")
        if count < 2:
            raise ValueError("count must be at least 2 for a race sweep")
        if count > MAX_RACE_REQUESTS:
            raise ValueError(
                f"at most {MAX_RACE_REQUESTS} concurrent requests per race sweep")
        return count

    def _identity_registry(
        self,
        identities: Optional[List[Identity]],
        baseline_identity: Optional[str],
        role: str = "identity",
    ) -> tuple[Dict[str, Identity], str]:
        """Validate declared identities and resolve which one the run acts as.

        Identities arrive as models through the MCP surface and as plain dicts
        through the REST bridge, so both are accepted rather than making the
        caller construct the model by hand.
        """
        registry: Dict[str, Identity] = {}
        for identity in identities or []:
            if isinstance(identity, dict):
                identity = Identity(**identity)
            if identity.label in registry:
                raise ValueError(f"duplicate identity label {identity.label!r}")
            if not identity.label or not isinstance(identity.label, str):
                raise ValueError("identity labels must be non-empty strings")
            registry[identity.label] = identity
        label = ""
        if baseline_identity:
            if baseline_identity not in registry:
                raise ValueError(
                    f"unknown {role} {baseline_identity!r}; declared: "
                    f"{sorted(registry) or 'none'}"
                )
            label = baseline_identity
        return registry, label

    async def race(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
        count: int = 3,
        identities: Optional[List[Identity]] = None,
        identity: Optional[str] = None,
    ) -> ProbeRace:
        """Send one identical request several times at once and return every capture.

        This is how a missing lock becomes observable from outside: a
        single-use action should honour only the first of several simultaneous
        requests, so a success count above one is the signal. Only a small
        fixed number of concurrent requests is ever sent.

        Every request in the burst is sent as the same ``identity``, which is the
        point: a coupon that can be redeemed twice concurrently by *one* user is
        a serialization bug, while two different users redeeming it once each is
        correct behaviour. Identity headers are applied to every request in the
        burst and then scrubbed from the captures, so the evidence records which
        account acted without carrying its session token.
        """
        url = self._validate_url(url)
        method = self._validate_method(method)
        count = self._validate_race_count(count)

        registry, label = self._identity_registry(identities, identity)
        burst_headers = dict(headers or {})
        if label:
            # Applied last, so a caller-supplied header cannot override the
            # credential the burst is supposed to be acting with.
            burst_headers.update(registry[label].headers)

        captures = await asyncio.gather(*(
            self.probe(
                url=url, method=method, headers=dict(burst_headers), body=body,
                timeout=timeout, follow_redirects=follow_redirects,
            )
            for _ in range(count)
        ))
        return ProbeRace(
            requested_url=url,
            method=method,
            captures=[
                _scrub_identity_headers(c.model_dump(), label) for c in captures
            ],
            count=count,
            total_requests=len(captures),
            identity=label,
            identities_used=[label] if label else [],
        )

    def _validate_threshold_count(self, count: int) -> int:
        """A threshold sweep needs enough requests to see a budget, never many.

        One request cannot demonstrate a rate limit: it can only show that a
        single request was not refused. The lower bound is therefore 2.
        """
        if not isinstance(count, int) or isinstance(count, bool):
            raise ValueError("count must be an integer")
        if count < 2:
            raise ValueError("count must be at least 2 for a threshold sweep")
        if count > MAX_THRESHOLD_REQUESTS:
            raise ValueError(
                f"at most {MAX_THRESHOLD_REQUESTS} requests per threshold sweep")
        return count

    async def threshold(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
        count: int = 10,
        interval: float = THRESHOLD_INTERVAL,
        identities: Optional[List[Identity]] = None,
        identity: Optional[str] = None,
    ) -> ProbeThreshold:
        """Send one request ``count`` times in sequence and record where throttling starts.

        Absence of a rate limit is only observable by exceeding one, so this asks
        a target to refuse some traffic and reports the index of the first
        refusal. Requests are deliberately *not* concurrent: a rate limiter
        counts arrivals over a window, and a simultaneous burst measures a
        different property than the one under test.
        """
        url = self._validate_url(url)
        method = self._validate_method(method)
        count = self._validate_threshold_count(count)
        if not isinstance(interval, (int, float)) or isinstance(interval, bool):
            raise ValueError("interval must be a number")
        # Bounded so a sweep cannot be used to hold a connection open, and so the
        # sweep cannot silently take hours.
        interval = max(0.0, min(float(interval), 5.0))

        registry, label = self._identity_registry(identities, identity)
        request_headers = dict(headers or {})
        if label:
            request_headers.update(registry[label].headers)

        captures: List[Dict[str, Any]] = []
        statuses: List[int] = []
        throttled_at = 0
        for index in range(count):
            capture = await self.probe(
                url=url, method=method, headers=dict(request_headers), body=body,
                timeout=timeout, follow_redirects=follow_redirects,
            )
            captures.append(_scrub_identity_headers(capture.model_dump(), label))
            status = capture.status_code
            if capture.reached_target:
                statuses.append(status)
                if status in THROTTLE_STATUSES and not throttled_at:
                    throttled_at = index + 1
            # No pause after the final request.
            if index + 1 < count and interval:
                await asyncio.sleep(interval)

        throttled = [s for s in statuses if s in THROTTLE_STATUSES]
        return ProbeThreshold(
            requested_url=url,
            method=method,
            captures=captures,
            count=count,
            total_requests=len(captures),
            throttled_at=throttled_at,
            throttled_count=len(throttled),
            throttle_statuses=throttled,
            rate_limited=bool(throttled),
            identity=label,
            identities_used=[label] if label else [],
        )

    def _validate_timing_repeats(self, repeats: int) -> int:
        if not isinstance(repeats, int) or isinstance(repeats, bool):
            raise ValueError("repeats must be an integer")
        if repeats < MIN_TIMING_REPEATS:
            raise ValueError(
                f"repeats must be at least {MIN_TIMING_REPEATS} for a timing harness"
            )
        if repeats > MAX_TIMING_REPEATS:
            raise ValueError(
                f"at most {MAX_TIMING_REPEATS} repeats per timing harness"
            )
        return repeats

    async def timing(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
        repeats: int = 3,
        interval: float = 0.0,
        identities: Optional[List[Identity]] = None,
        identity: Optional[str] = None,
    ) -> ProbeTiming:
        """Send one request ``repeats`` times and return median elapsed_ms."""
        url = self._validate_url(url)
        method = self._validate_method(method)
        repeats = self._validate_timing_repeats(repeats)
        if not isinstance(interval, (int, float)) or isinstance(interval, bool):
            raise ValueError("interval must be a number")
        interval = max(0.0, min(float(interval), 5.0))

        registry, label = self._identity_registry(identities, identity)
        request_headers = dict(headers or {})
        if label:
            request_headers.update(registry[label].headers)

        captures: List[Dict[str, Any]] = []
        samples: List[float] = []
        for index in range(repeats):
            capture = await self.probe(
                url=url,
                method=method,
                headers=dict(request_headers),
                body=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
            )
            captures.append(_scrub_identity_headers(capture.model_dump(), label))
            if capture.reached_target and capture.elapsed_ms is not None:
                samples.append(float(capture.elapsed_ms))
            if index + 1 < repeats and interval:
                await asyncio.sleep(interval)

        median = None
        if samples:
            s = sorted(samples)
            m = len(s) // 2
            median = (s[m - 1] + s[m]) / 2.0 if len(s) % 2 == 0 else s[m]

        return ProbeTiming(
            requested_url=url,
            method=method,
            captures=captures,
            repeats=repeats,
            total_requests=len(captures),
            reached_count=len(samples),
            elapsed_ms_samples=samples,
            median_elapsed_ms=median,
            identity=label,
            identities_used=[label] if label else [],
        )

    def _validate_smuggle_headers(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Headers for a smuggling attempt: framing allowed, routing not.

        Stricter than :meth:`_validate_headers` on purpose. ``Host`` is refused
        because the hidden request's Host is the only thing keeping a desync
        aimed at this target, and that value is written by the tool.
        """
        return self._validate_headers(
            headers, blocked=BLOCKED_SMUGGLE_HEADERS,
            reason="defines the request framing or routing and cannot be set when testing smuggling",
        )

    @staticmethod
    def _smuggle_authority(parsed) -> str:
        """``host:port`` for the socket dial, with the default port filled in.

        Deliberately the same normalisation the grant uses, so the destination
        the tool dials is the destination the grant named. If these two
        disagreed, the gate would be authorising one port while the tool
        dialled another.
        """
        host = (parsed.hostname or "").lower()
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{port}"

    @staticmethod
    def _smuggle_canary_path(path: str, token: str) -> str:
        """Build the hidden request's path from the caller's path plus a token.

        Derived from the caller's own path so it stays on the same origin, and
        suffixed with a per-attempt token so a cached or replayed response cannot
        be mistaken for this attempt's evidence. Any real application 404s a path
        it does not recognise, and that 404 is how the hidden request is later
        told apart from the confirmation.
        """
        base = path or "/"
        if base == "/":
            return f"/{SMUGGLE_CANARY_SUFFIX}-{token}"
        return f"{base.rstrip('/')}/{SMUGGLE_CANARY_SUFFIX}-{token}"

    @staticmethod
    def _smuggle_exchange(
        method: str,
        path: str,
        authority: str,
        variant: str,
        canary_path: str,
        extra_headers: Dict[str, str],
    ) -> str:
        """Build the two-request exchange for one ambiguity pair.

        Both variants send the same bytes over the wire -- a request whose visible
        body is an empty chunked stream, followed by the hidden request -- and
        differ only in the ``Content-Length`` they advertise. That is the whole
        trick: the number the front-end trusts and the number the back-end
        trusts now disagree, and the hidden request is left pending in whichever
        of the two read the framing differently.

          * ``cl_te``: ``Content-Length`` covers the hidden request too, so a
            front-end that trusts CL forwards it and a back-end that trusts TE
            stops at the empty chunk, leaving the hidden request queued behind it.
          * ``te_cl``: ``Content-Length`` covers only the hidden request, so a
            front-end that trusts TE forwards just the terminator and queues the
            hidden request itself.

        Neither variant lets the caller influence the hidden request, and the
        hidden request's Host is always ``authority`` -- the same origin the
        caller asked for.
        """
        hidden = f"GET {canary_path} HTTP/1.1\r\nHost: {authority}\r\n\r\n"
        terminator = "0\r\n\r\n"
        content_length = len(terminator) + len(hidden) if variant == "cl_te" else len(hidden)

        rendered = "".join(f"{k}: {v}\r\n" for k, v in extra_headers.items())
        ambiguous = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"{rendered}"
            f"Content-Length: {content_length}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{terminator}{hidden}"
        )
        # The confirmation. If the target split the first request in two, the
        # answer to this one is not the first thing that comes back.
        confirmation = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"{rendered}"
            f"\r\n"
        )
        return ambiguous + confirmation

    @staticmethod
    def _final_statuses(data: bytes) -> List[int]:
        """Status codes in ``data``, with informational (1xx) ones dropped.

        ``100 Continue`` and ``103 Early Hints`` are answers *to* a request, not
        extra requests. Counting them would make any target that uses them look
        desyncable.
        """
        return [
            int(m) for m in re.findall(rb"HTTP/1\.[01] (\d{3})", data)
            if not m.startswith(b"1")
        ]

    @staticmethod
    async def _smuggle_statuses(
        reader: asyncio.StreamReader,
        expected: int,
        deadline: float,
        cap: int = MAX_SMUGGLE_RESPONSE_BYTES,
        grace: float = SMUGGLE_DESYNC_GRACE_SECONDS,
    ) -> List[int]:
        """Collect final response statuses, then keep listening past ``expected``.

        A desync is detected by a response *beyond* the number of requests that
        were written, so stopping at ``expected`` would stop one answer short of
        the evidence: the extra status has not been produced yet when the
        expected ones are all in hand, and it arrives a moment later. Reading
        exactly what we expected is how a real desync gets reported as "nothing
        unusual" on a slow run and found on a fast one.

        So once the expected count is reached the reader stays open for ``grace``
        seconds, and only a genuine silence (or the deadline) ends the wait. The
        grace window is what makes the count meaningful, and it is bounded so a
        target that never closes cannot hold the tool open.

        Returns the statuses in order. A target that closes right after the split
        is a desync too, and shows up here as the window ending early.
        """
        buf = b""
        loop = asyncio.get_event_loop()
        grace_deadline: Optional[float] = None

        while len(buf) < cap:
            remaining = deadline - loop.time()
            if grace_deadline is not None:
                remaining = min(remaining, grace_deadline - loop.time())
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except (asyncio.TimeoutError, ConnectionError):
                break
            if not chunk:
                break
            buf += chunk
            if grace_deadline is None and len(HttpProbeServer._final_statuses(buf)) >= expected:
                grace_deadline = loop.time() + grace
        return HttpProbeServer._final_statuses(buf)

    @staticmethod
    def _smuggle_split(
        statuses: List[int], sent: int = SMUGGLE_REQUESTS_SENT_PER_VARIANT
    ) -> tuple:
        """Decide whether the target parsed one of our requests as two.

        Two independent signals, because neither covers every real desync:

          * **More answers than requests.** We sent ``sent`` requests; if the
            target answers more than that on the same connection it served a
            request nobody sent separately. This is the sound one, and it holds
            whatever the hidden request happened to return.
          * **The hidden request answered in place of ours.** A front-end that
            swallows our request and forwards the leftover serves the canary
            first and the caller's own path last. The last status is therefore
            the caller's path's real answer, which is what makes a leading 404
            meaningful.

        The leading-404 test needs the confirmation's status to be trustworthy,
        which is why it also checks the tail. A caller pointing this at a path
        that itself 404s sees 404 on both ends and is correctly not flagged --
        without that guard, every probe of a missing endpoint would "confirm"
        smuggling.
        """
        extra = len(statuses) - sent
        canary_first = bool(
            len(statuses) >= 2
            and statuses[0] == SMUGGLE_NOT_FOUND
            and statuses[-1] != SMUGGLE_NOT_FOUND
        )
        split = extra > 0 or canary_first
        canary_served = canary_first or SMUGGLE_NOT_FOUND in statuses[1:-1]
        if extra > 0:
            note = (
                f"target answered {len(statuses)} requests it was sent {sent}: "
                "framing disagree")
        elif canary_first:
            note = "hidden request was answered instead of the caller's own path"
        else:
            note = "no framing disagreement observed for this variant"
        return split, canary_served, note

    async def smuggle(
        self,
        url: str,
        variant: str = "both",
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 20.0,
        identities: Optional[List[Identity]] = None,
        identity: Optional[str] = None,
    ) -> ProbeSmuggle:
        """Test whether a front-end and back-end disagree about request framing.

        A proxy chain is only as safe as the least consistent hop in it. If the
        front-end decides a request ends at one byte and the back-end at another,
        the leftover bytes become the start of the next request the back-end
        serves -- an attacker-supplied request the front-end never approved. That
        is how request smuggling turns into hijacked sessions and poisoned caches.

        This sends one ambiguous request plus one confirmation per variant on a
        single connection, then compares the answers to the requests. If the
        target replies more times than it was asked, or answers the hidden
        request in place of the caller's, it parsed one request as two: that is
        a desync. Grade against ``desync_detected``, and read ``attempts`` for
        the statuses and which variant split.

        What it deliberately will not do: accept caller-authored smuggled bytes,
        or send the hidden request at any destination other than the target's own
        authority. A general desync primitive is a weapon pointed at whoever the
        operator happens to be scanning, so the hidden request is generated here
        and the budget is four requests across at most two connections.

        Test this only where you are authorized. It sends deliberately malformed
        framing, which is exactly what WAFs and hardening middleware flag.
        """
        url = self._validate_url(url)
        method = self._validate_method(method)
        variant = (variant or "both").strip().lower()
        if variant not in ("both",) + SMUGGLE_VARIANTS:
            raise ValueError(f"variant must be 'cl_te', 'te_cl' or 'both', got '{variant}'")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("timeout must be a number")
        timeout = max(1.0, min(float(timeout), SMUGGLE_TIMEOUT_CEILING))

        requested = (
            list(SMUGGLE_VARIANTS) if variant == "both" else [variant]
        )
        if len(requested) > MAX_SMUGGLE_VARIANTS:
            raise ValueError(f"at most {MAX_SMUGGLE_VARIANTS} variants per attempt")

        parsed = urlparse(url)
        authority = self._smuggle_authority(parsed)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        registry, label = self._identity_registry(identities, identity)
        extra_headers = self._validate_smuggle_headers(headers)
        if label:
            # An authenticated smuggle is the interesting one: it is how a
            # desync becomes account takeover rather than a stray 404. The token
            # goes on the wire and is kept out of the evidence.
            extra_headers.update(registry[label].headers)

        attempts: List[SmuggleAttempt] = []
        total_requests = 0
        for name in requested:
            token = secrets.token_hex(6)
            canary = self._smuggle_canary_path(path.split("?")[0], token)
            wire = self._smuggle_exchange(
                method, path, authority, name, canary, extra_headers)
            # The preview is rebuilt with redacted header values rather than
            # redacted afterwards. ``redact_text`` understands JSON and query
            # strings, not a raw ``Authorization:`` line, so scrubbing the
            # finished wire would have let the session token straight through
            # into the evidence. Redacting the headers before they are rendered
            # is the only ordering that cannot leak.
            preview = redact_text(self._smuggle_exchange(
                method, path, authority, name, canary, redact_headers(extra_headers)))

            statuses: List[int] = []
            note = ""
            try:
                ssl_ctx = (
                    ssl.create_default_context() if parsed.scheme == "https" else None
                )
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                        ssl=ssl_ctx,
                    ),
                    timeout=timeout,
                )
            except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
                note = f"could not open a connection: {type(exc).__name__}: {exc}"
                attempts.append(SmuggleAttempt(
                    variant=name, canary_path=canary, sent_preview=preview,
                    statuses=[], requests_sent=0, responses_received=0,
                    canary_served=False, split_detected=False, note=note))
                continue

            try:
                total_requests += SMUGGLE_REQUESTS_RECEIVED_PER_VARIANT
                deadline = asyncio.get_event_loop().time() + timeout
                writer.write(wire.encode("latin-1"))
                await asyncio.wait_for(writer.drain(), timeout=timeout)
                statuses = await self._smuggle_statuses(
                    reader, SMUGGLE_REQUESTS_SENT_PER_VARIANT, deadline)
            except (asyncio.TimeoutError, OSError) as exc:
                note = f"exchange did not complete: {type(exc).__name__}: {exc}"
            finally:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except (asyncio.TimeoutError, OSError):
                    pass

            # More answers than requests is the desync. The canary records what
            # got smuggled; it is not the verdict, because a target that happens
            # to 404 the caller's own path would otherwise flag every probe.
            split, canary_served, split_note = self._smuggle_split(statuses)
            if not note:
                note = split_note
            attempts.append(SmuggleAttempt(
                variant=name, canary_path=canary, sent_preview=preview,
                statuses=statuses,
                requests_sent=SMUGGLE_REQUESTS_SENT_PER_VARIANT,
                responses_received=len(statuses),
                canary_served=canary_served,
                split_detected=split, note=note))

        return ProbeSmuggle(
            requested_url=url,
            method=method,
            authority=authority,
            variants_tried=requested,
            attempts=attempts,
            desync_detected=any(a.split_detected for a in attempts),
            total_requests=total_requests,
            identity=label,
            identities_used=[label] if label else [],
        )

    def _validate_websocket_headers(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
        """Headers for a WebSocket handshake: everything that defines it is ours.

        Same shape as the smuggling check -- validate normally, then refuse the
        names the tool has to own, and then refuse the names that would make the
        run something other than the anonymous visit it is recorded as.
        """
        validated = self._validate_headers(
            headers, blocked=BLOCKED_WEBSOCKET_HEADERS,
            reason="defines the WebSocket handshake and cannot be set",
        )
        return self._validate_headers(
            validated, blocked=BLOCKED_WEBSOCKET_AUTH_HEADERS,
            reason=(
                "carries a credential; an identity must be declared as one so "
                "the run is recorded as authenticated rather than anonymous"
            ),
        )

    @staticmethod
    def _ws_accept_for(key: str) -> str:
        """The value a correct server must echo back for this key."""
        digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        return base64.b64encode(digest).decode("ascii")

    @staticmethod
    def _ws_encode_frame(payload: bytes, opcode: int = 0x1) -> bytes:
        """Encode one client frame, masked as RFC 6455 requires.

        Clients must mask; a server that will not accept an unmasked frame is
        doing the one thing the spec makes mandatory, so the harness cannot
        quietly skip it.
        """
        mask = secrets.token_bytes(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        header = bytes([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header += bytes([0x80 | length])
        elif length < (1 << 16):
            header += bytes([0x80 | 126]) + length.to_bytes(2, "big")
        else:
            header += bytes([0x80 | 127]) + length.to_bytes(8, "big")
        return header + mask + masked

    @staticmethod
    async def _ws_read_frames(
        reader: asyncio.StreamReader,
        deadline: float,
        limit: int = WS_MAX_FRAMES_READ,
        initial: bytes = b"",
    ) -> List[WebSocketFrame]:
        """Decode up to ``limit`` frames, stopping at the cap or the deadline.

        ``initial`` is bytes already read off the socket -- a frame that arrived
        in the same segment as the handshake response would otherwise be lost,
        and that frame is usually the interesting one.

        Deliberately shallow: the question is whether the server starts talking
        unprompted, not what it can be made to say.
        """
        buf = initial
        loop = asyncio.get_event_loop()
        frames: List[WebSocketFrame] = []

        async def pull() -> None:
            nonlocal buf
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            if not chunk:
                raise ConnectionError
            buf += chunk

        while len(frames) < limit:
            try:
                # A frame header is at least two bytes; a large frame also needs
                # its extended length, so read until the length is knowable.
                while len(buf) < 2:
                    await pull()
                opcode = buf[0] & 0x0F
                masked = bool(buf[1] & 0x80)
                length = buf[1] & 0x7F
                offset = 2
                if length == 126:
                    while len(buf) < offset + 2:
                        await pull()
                    length = int.from_bytes(buf[offset:offset + 2], "big")
                    offset += 2
                elif length == 127:
                    while len(buf) < offset + 8:
                        await pull()
                    length = int.from_bytes(buf[offset:offset + 8], "big")
                    offset += 8
                truncated = length > WS_MAX_FRAME_BYTES
                take = min(length, WS_MAX_FRAME_BYTES)
                if masked:
                    while len(buf) < offset + 4:
                        await pull()
                    offset += 4
                while len(buf) < offset + take:
                    await pull()
                payload = buf[offset:offset + take]
                buf = buf[offset + length:]
                frames.append(WebSocketFrame(
                    opcode=opcode,
                    payload_preview=redact_text(payload[:512].decode("utf-8", "replace")),
                    payload_bytes=length,
                    truncated=truncated,
                ))
                # A close frame ends the conversation.
                if opcode == 0x8:
                    break
            except (asyncio.TimeoutError, ConnectionError, OSError):
                break
        return frames

    async def websocket_auth(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        message: str = "ping",
        timeout: float = 10.0,
        identities: Optional[List[Identity]] = None,
        identity: Optional[str] = None,
    ) -> ProbeWebSocketAuth:
        """Open a WebSocket as an anonymous visitor and see whether it is allowed.

        A WebSocket handshake is an ordinary HTTP GET, so a browser will send one
        to another origin with the victim's cookies attached, and there is no
        navigation prompt to interrupt it. That makes "who may open this socket"
        the question, not "is the socket encrypted".

        This completes a real RFC 6455 handshake with no credentials, checks the
        server echoed a correct ``Sec-WebSocket-Accept``, then reads a few frames
        *before* sending anything. A server that answers 101 and immediately
        starts pushing has handed a data stream to whoever asked, which is the
        finding; grade against ``findings``.

        Pass ``identities`` plus ``identity`` to repeat the upgrade as a known
        user. The difference between the two runs is what tells you whether the
        endpoint is checking anything, and the credential is withheld from the
        evidence either way.

        The handshake headers are generated here and are not settable, so this
        cannot be turned into a request that is not a WebSocket upgrade.
        """
        url = self._validate_url(url)
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
            raise ValueError("timeout must be a number")
        timeout = max(1.0, min(float(timeout), WS_TIMEOUT_CEILING))
        if not isinstance(message, str):
            raise ValueError("message must be a string")
        message = message[:WS_MAX_SEND_BYTES]

        parsed = urlparse(url)
        authority = self._smuggle_authority(parsed)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        registry, label = self._identity_registry(identities, identity)
        extra_headers = self._validate_websocket_headers(headers)
        if label:
            extra_headers.update(registry[label].headers)

        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        handshake = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: {WS_VERSION}\r\n"
            f"User-Agent: {DEFAULT_USER_AGENT}\r\n"
            + "".join(f"{k}: {v}\r\n" for k, v in extra_headers.items())
            + "\r\n"
        )

        result = ProbeWebSocketAuth(
            requested_url=url, authority=authority, identity=label,
            identities_used=[label] if label else [],
        )

        try:
            ssl_ctx = ssl.create_default_context() if parsed.scheme == "https" else None
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    parsed.hostname,
                    parsed.port or (443 if parsed.scheme == "https" else 80),
                    ssl=ssl_ctx,
                ),
                timeout=timeout,
            )
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
            result.note = f"could not open a connection: {type(exc).__name__}: {exc}"
            result.findings.append(WS_FINDING_UPGRADE_REJECTED)
            return result

        try:
            loop = asyncio.get_event_loop()
            deadline = loop.time() + timeout
            writer.write(handshake.encode("latin-1"))
            await asyncio.wait_for(writer.drain(), timeout=timeout)

            raw = b""
            while b"\r\n\r\n" not in raw:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
                if not chunk:
                    break
                raw += chunk

            if b"\r\n\r\n" not in raw:
                result.note = "connection closed before the handshake completed"
                result.findings.append(WS_FINDING_UPGRADE_REJECTED)
                return result

            head, _, rest = raw.partition(b"\r\n\r\n")
            head_text = head.decode("latin-1", "replace")
            first_line = head_text.split("\r\n")[0]
            parts = first_line.split(" ", 2)
            result.handshake_status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            result.upgrade_granted = result.handshake_status == 101

            response_headers = {}
            for line in head_text.split("\r\n")[1:]:
                if ":" in line:
                    name, _, value = line.partition(":")
                    response_headers[name.strip().lower()] = value.strip()

            if result.upgrade_granted:
                accept = response_headers.get("sec-websocket-accept", "")
                result.accept_valid = accept == self._ws_accept_for(key)
                if not result.accept_valid:
                    result.findings.append(WS_FINDING_ACCEPT_NOT_VALIDATED)
                if not label:
                    result.findings.append(WS_FINDING_UNAUTHENTICATED_UPGRADE)

                # Read what the server has to say *before* writing our message,
                # not after. A frame in that window cannot be a response to
                # anything we sent, so its presence settles the question -- and
                # deciding it any other way is wrong: judging it by whether the
                # greeting shared a segment with the handshake would make the
                # finding depend on TCP segmentation, so the same server would
                # report or not report based on the network.
                deadline = loop.time() + timeout
                result.frames = await self._ws_read_frames(
                    reader, deadline, initial=rest)
                if result.frames:
                    result.data_before_client_message = True
                    result.findings.append(WS_FINDING_DATA_BEFORE_AUTH)
                    writer.write(self._ws_encode_frame(message.encode("utf-8")))
                    await asyncio.wait_for(writer.drain(), timeout=timeout)
            else:
                result.findings.append(WS_FINDING_UPGRADE_REJECTED)
                result.note = (
                    f"upgrade refused with {result.handshake_status}; "
                    "the endpoint did check the request"
                )
        except (asyncio.TimeoutError, OSError, ssl.SSLError) as exc:
            result.note = f"exchange did not complete: {type(exc).__name__}: {exc}"
            if not result.findings:
                result.findings.append(WS_FINDING_UPGRADE_REJECTED)
        finally:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except (asyncio.TimeoutError, OSError):
                pass

        if result.upgrade_granted and not result.note:
            result.note = (
                "upgrade granted and the server spoke first" if result.frames
                else "upgrade granted; no unsolicited data observed"
            )
        return result

    def setup_tools(self):
        @self.mcp.tool()
        async def http_probe(
            url: str,
            method: str = "GET",
            headers: Optional[Dict[str, str]] = None,
            body=None,
            timeout: float = 20.0,
            follow_redirects: bool = False,
            caller: Optional[str] = None,
        ) -> ProbeCapture:
            """Send one exactly-specified HTTP request and return the full raw response.

            Use this to VALIDATE a finding rather than search for new ones:
            craft the specific request a hypothesis predicts, send it, and read
            the actual response. The returned capture is the proof-of-concept
            and the reproduction steps, so keep it verbatim as evidence.

            Redirects are not followed by default so the probe cannot wander
            onto a host outside the authorized scope.
            """
            self.verify_caller("http_probe", caller)
            return await self.probe(
                url=url, method=method, headers=headers, body=body,
                timeout=timeout, follow_redirects=follow_redirects,
                extract_token=True,
            )

        @self.mcp.tool()
        async def http_probe_diff(
            url: str,
            variants: List[ProbeVariant],
            method: str = "GET",
            headers: Optional[Dict[str, str]] = None,
            body=None,
            timeout: float = 20.0,
            follow_redirects: bool = False,
            identities: Optional[List[Identity]] = None,
            baseline_identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeComparison:
            """Send a request, then re-send it with deliberate changes, and diff the results.

            Use this when a bug would only show up as a *difference* in behaviour:
            broken object-level authorization, input handling, error-based
            disclosure, mass assignment. Craft each variant to encode one specific
            hypothesis and label it with that hypothesis, then read which
            variants produced a material difference.

            Every variant must target the same host, port and scheme as the
            baseline, so a difference can only be caused by the change under test.
            A difference counts as material only if it survives normalization of
            expected volatile fields (timestamps, nonces, CSRF tokens), so
            re-rendered pages will not read as findings.

            To test authorization, declare the test accounts as named `identities`
            and point variants at them by label. Use only accounts you own or are
            authorized to test with. Credential values are used to send the
            request and then withheld from the evidence; only the label is kept.
            """
            self.verify_caller("http_probe_diff", caller)
            return await self.compare(
                url=url, variants=variants, method=method, headers=headers,
                body=body, timeout=timeout, follow_redirects=follow_redirects,
                identities=identities, baseline_identity=baseline_identity,
            )

        @self.mcp.tool()
        async def http_probe_race(
            url: str,
            method: str = "POST",
            headers: Optional[Dict[str, str]] = None,
            body=None,
            timeout: float = 20.0,
            follow_redirects: bool = False,
            count: int = 3,
            identities: Optional[List[Identity]] = None,
            identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeRace:
            """Send the same request several times concurrently and return every capture.

            Use this for a single-use action — coupon redemption, account
            creation, checkout, vote, transfer — where the interesting question
            is whether the endpoint serializes the operation. Fire a small
            fixed number of identical simultaneous requests and count the
            successes: if more than one succeeds, the action was not serialized
            and a one-shot capability can be replayed.

            Pass ``identities`` plus ``identity`` to run the whole burst as one
            authenticated user. That is the meaningful test: one account
            redeeming a coupon twice at once is a serialization bug, while two
            accounts redeeming it once each is correct. The session token is
            applied to every request and then withheld from the evidence, which
            records the identity label instead.

            Every capture is returned, so the success count is reviewable rather
            than taken on trust. Only send this against a target you are
            authorized to test; the request is repeated, so keep ``count`` at the
            small default.
            """
            self.verify_caller("http_probe_race", caller)
            return await self.race(
                url=url, method=method, headers=headers, body=body,
                timeout=timeout, follow_redirects=follow_redirects, count=count,
                identities=identities, identity=identity,
            )

        @self.mcp.tool()
        async def http_probe_threshold(
            url: str,
            method: str = "GET",
            headers: Optional[Dict[str, str]] = None,
            body=None,
            timeout: float = 20.0,
            follow_redirects: bool = False,
            count: int = 10,
            interval: float = THRESHOLD_INTERVAL,
            identities: Optional[List[Identity]] = None,
            identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeThreshold:
            """Send one request several times in sequence to find where throttling starts.

            Use this for a missing rate limit on login, password reset, coupon
            validation, or any expensive endpoint. A rate limit can only be shown
            to be absent by sending enough traffic to have crossed one, so this
            repeats the request up to ``count`` times and reports the index of
            the first refusal. If nothing is refused, the endpoint has no
            observable throttle within the tested range.

            The requests are sequential on purpose: a rate limiter counts request
            arrivals over a window, so a simultaneous burst would measure
            concurrency rather than the budget. Grade against ``throttled_at``
            being 0 (no throttle observed) rather than against a raw status.

            Only send this against a target you are authorized to test, and keep
            ``count`` at the smallest value that answers the question.
            """
            self.verify_caller("http_probe_threshold", caller)
            return await self.threshold(
                url=url, method=method, headers=headers, body=body,
                timeout=timeout, follow_redirects=follow_redirects, count=count,
                interval=interval, identities=identities, identity=identity,
            )

        @self.mcp.tool()
        async def http_probe_timing(
            url: str,
            method: str = "GET",
            headers: Optional[Dict[str, str]] = None,
            body=None,
            timeout: float = 20.0,
            follow_redirects: bool = False,
            repeats: int = 3,
            interval: float = 0.0,
            identities: Optional[List[Identity]] = None,
            identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeTiming:
            """Send one request repeatedly and return median elapsed_ms."""
            self.verify_caller("http_probe_timing", caller)
            return await self.timing(
                url=url,
                method=method,
                headers=headers,
                body=body,
                timeout=timeout,
                follow_redirects=follow_redirects,
                repeats=repeats,
                interval=interval,
                identities=identities,
                identity=identity,
            )

        @self.mcp.tool()
        async def http_probe_smuggle(
            url: str,
            variant: str = "both",
            method: str = "POST",
            headers: Optional[Dict[str, str]] = None,
            timeout: float = 20.0,
            identities: Optional[List[Identity]] = None,
            identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeSmuggle:
            """Test whether a proxy chain disagrees about where a request ends.

            A front-end that trusts Content-Length and a back-end that trusts
            Transfer-Encoding read different numbers of bytes out of the same
            request, and the difference becomes the start of the next request the
            back-end serves. That is request smuggling, and it is how a smuggled
            request steals another user's session or poisons a cache.

            Sends one ambiguous request and one confirmation per variant on a
            single connection, then compares the answers to the requests. If the
            target replies more times than it was asked, or answers the hidden
            request in place of the caller's, it parsed one request as two.
            Grade against ``desync_detected``, and read ``attempts`` for the
            statuses and which variant split.

            Bounded on purpose, because this is the one tool here that can send a
            request the caller did not write: you supply the URL and the variant
            name, and the hidden request is generated against the target's own
            authority. It cannot be pointed at a third party, and ``Host`` is not
            settable so the hidden request cannot claim to be somewhere else.
            Four requests, two connections, per call.

            An authenticated test is the one that matters -- that is how a desync
            becomes account takeover -- so pass ``identities`` plus ``identity`` to
            smuggle a session. The credential is sent and then withheld from the
            evidence.

            Only send this to a target you are authorized to test, and expect
            hardened stacks to reject the malformed framing outright; that is a
            clean negative, not an error.
            """
            self.verify_caller("http_probe_smuggle", caller)
            return await self.smuggle(
                url=url, variant=variant, method=method, headers=headers,
                timeout=timeout, identities=identities, identity=identity,
            )

        @self.mcp.tool()
        async def http_probe_websocket_auth(
            url: str,
            headers: Optional[Dict[str, str]] = None,
            message: str = "ping",
            timeout: float = 10.0,
            identities: Optional[List[Identity]] = None,
            identity: Optional[str] = None,
            caller: Optional[str] = None,
        ) -> ProbeWebSocketAuth:
            """Open a WebSocket as an anonymous visitor and see whether that is allowed.

            A WebSocket handshake is an ordinary HTTP GET, so a browser will send
            one to another origin with the victim's cookies attached and never
            prompt the user about it. The question worth asking is therefore not
            "is this encrypted" but "who is allowed to open this socket, and does
            the server notice when nobody is".

            Completes a real RFC 6455 handshake with no credentials, verifies the
            server echoed a correct Sec-WebSocket-Accept, then reads a few frames
            *before* sending anything. A server that answers 101 and immediately
            starts pushing has handed a live data stream to whoever asked.

            Grade against ``findings``, which are fixed strings:
              * ``unauthenticated_upgrade_granted`` -- 101 with no credentials sent.
              * ``data_served_before_any_client_message`` -- it then pushed anyway.
              * ``sec_websocket_accept_missing_or_invalid`` -- the reply did not
                prove it was addressed to this request, which is the check that
                stops a malicious page reading a cross-origin socket.
              * ``upgrade_rejected`` -- the endpoint did check, and said no.

            Pass ``identities`` plus ``identity`` to repeat the upgrade as a known
            user; comparing the two runs is what shows whether the endpoint is
            checking anything. The credential is sent and then withheld from the
            evidence.

            One handshake and a handful of frames, and the handshake headers are
            generated here rather than accepted from you, so this cannot become a
            request that is not a WebSocket upgrade.
            """
            self.verify_caller("http_probe_websocket_auth", caller)
            return await self.websocket_auth(
                url=url, headers=headers, message=message, timeout=timeout,
                identities=identities, identity=identity,
            )
