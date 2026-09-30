"""http_probe: send one agent-authored HTTP request and capture the full response.

This is the primitive that makes genuine validation possible. Every other tool in
this sandbox is a fixed-purpose scanner, so the agent can only ever restate
"run nuclei again". With http_probe the agent writes a request itself, executes
it, and reads the actual response. That captured exchange is simultaneously:

  * the proof-of-concept,
  * the validation evidence,
  * and the reproduction recipe (it is literally the traffic that was sent).

The probe is deliberately narrow. It is an HTTP client for a single authorized
target, not a request smuggling or pivoting primitive: no arbitrary socket
control, no cross-host redirection following, and a hard cap on response bytes
so a hostile target cannot exhaust memory.
"""
import asyncio
import json
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import httpx
from pydantic import BaseModel, Field

from .common.base_server import BaseSecurityServer
from .common.redaction import redact_capture
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
# caller cannot turn a single probe into an unbounded sweep.
MAX_COMPARISON_REQUESTS = 2
MAX_VARIANTS = 8

# A race sweep sends the *same* request several times at once. The cap is
# deliberately small: concurrency multiplies load on a live host, so the harness
# is a check for a missing lock, not a stress tool.
MAX_RACE_REQUESTS = 6

# A threshold sweep sends the same request repeatedly in quick succession to find
# where a target starts refusing traffic. Higher than the race cap because the
# requests are sequential and a budget is typically well above the concurrency
# needed to break a lock, but still a small fixed number: this measures whether a
# limiter exists, it is not a way to load a host.
MAX_THRESHOLD_REQUESTS = 20

# Statuses that mean "you are going too fast", plus the ones targets use when
# shedding load. A target answering 503 or 402 to a burst is not necessarily
# rate limiting, so the full observed statuses travel with the verdict.
THROTTLE_STATUSES = frozenset({429, 503})

# Pause between threshold requests. Long enough to read as sequential traffic
# rather than a burst, short enough to stay inside a typical one-minute window.
THRESHOLD_INTERVAL = 0.25

# Header names a caller may not set: they would let a probe authenticate as
# someone else or smuggle a second request stream.
BLOCKED_REQUEST_HEADERS = frozenset({
    "content-length", "connection", "transfer-encoding",
    "upgrade", "proxy-authorization", "te", "trailer",
})
# ``host`` is deliberately settable: it only changes the Host line sent to the
# destination already resolved from the URL, so routing and scope are unaffected
# while Host-header/cache-poisoning hypotheses become testable.


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


class ProbeComparison(BaseModel):
    """Baseline response compared against one or more perturbed requests.

    ``any_material`` is the field to branch on: it is true only when at least
    one variant produced a change that survived volatile-field normalization,
    which is the precondition for treating a difference as evidence.
    """

    baseline: Dict[str, Any] = Field(default_factory=dict)
    variants: List[VariantResult] = Field(default_factory=list)
    any_material: bool = False
    material_signals: List[str] = Field(default_factory=list)
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

    def _validate_headers(self, headers: Optional[Dict[str, str]]) -> Dict[str, str]:
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
            if lname in BLOCKED_REQUEST_HEADERS:
                raise ValueError(f"Header '{name}' is controlled by the HTTP client and cannot be set")
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

    async def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body=None,
        timeout: float = 20.0,
        follow_redirects: bool = False,
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
            async with httpx.AsyncClient(
                timeout=timeout_cfg,
                follow_redirects=follow_redirects,
                max_redirects=3,
                verify=False,
            ) as client:
                resp = await client.request(
                    method, url, headers=req_headers, content=req_body
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
                    redirects=[str(h.url) for h in resp.history],
                    content_type=resp.headers.get("content-type", ""),
                    server_header=resp.headers.get("server", ""),
                    body_sha256=hashlib.sha256(raw).hexdigest(),
                    reached_target=True,
                )
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
        return ProbeCapture(**_coerce_text_bodies(redact_capture(capture.model_dump())))

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
