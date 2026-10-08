"""Structural comparison of two response captures.

Most interesting web vulnerabilities are differential rather than absolute. A
server returning 500 to everybody is not a finding; a server returning another
user's record to you, or a stack trace only when you add a quote, is. A single
capture cannot express that, so the probe can send a baseline and a variant and
hand both to this module to say *what actually changed*.

The comparison is deliberately conservative about what it calls interesting.
Reporting every byte of drift would drown the signal, so differences are grouped
into security-relevant categories and a plain "the page re-rendered" difference
is reported as uninteresting rather than as a finding.
"""
import re
from typing import Any, Dict, List, Optional

# Headers whose presence, absence, or value change is security-relevant.
SECURITY_RELEVANT_HEADERS = frozenset({
    "set-cookie", "location", "www-authenticate", "authorization",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-allow-methods",
    "content-security-policy", "strict-transport-security", "x-frame-options",
    "x-content-type-options", "server", "x-powered-by", "content-type",
    "content-length", "vary", "allow", "link",
})

# Value shapes that suggest the response handed back something it should not.
_LEAK_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "uuid": re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
    ),
    "stack_trace": re.compile(
        r"(Traceback \(most recent call last\)|"
        r"java\.lang\.\w+Exception|"
        r"at [\w.$]+\([\w]+\.java:\d+\)|"
        r"\.php:\d+|SQLSTATE\[|ORA-\d{5})"
    ),
    "sql_error": re.compile(
        r"(syntax error at or near|unclosed quotation mark|SQLSTATE|"
        r"ORA-\d{5}|mysql_fetch|pg_query|PDOException)", re.IGNORECASE
    ),
    "private_key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "aws_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "password_field": re.compile(
        r'"(?:password|passwd|pwd|secret|token)"\s*:\s*"(?!\[REDACTED\]|\*{3})[^"]{3,}"',
        re.IGNORECASE,
    ),
    "sensitive_path": re.compile(
        r"(/etc/passwd|/etc/shadow|/proc/self|win\.ini|"
        r"WEB-INF/web\.xml|/\.env|\.git/config|\.aws/credentials)", re.IGNORECASE
    ),
    "internal_hostname": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    ),
}

# A response time gap this large is worth reporting; below it, network jitter
# alone produces the same signal far too often to be evidence.
TIMING_SIGNIFICANCE_MS = 1000

# Bodies an edge defense serves *instead of* the application. When a payload
# provokes one of these while the baseline did not, the request was rejected
# before it reached the code under test, so the two responses are not
# comparable and the difference says nothing about the application's behavior.
_WAF_BLOCK_BODY = re.compile(
    r"(attention required|access denied|access to this page has been denied|"
    r"request blocked|you have been blocked|web application firewall|"
    r"cloudflare ray id|error code:\s*1\d{3}|"
    r"the action you have requested is not allowed|"
    r"your request has been blocked)",
    re.IGNORECASE,
)

# Vendor codes that identify an edge rule (rather than the origin) as the thing
# that produced the response.
_EDGE_RULE_MARKERS = re.compile(
    r"(error code:\s*(?:100\d|1010|1011|1020|102\d)|ray id)",
    re.IGNORECASE,
)


def _status_of(capture: Dict[str, Any]) -> Optional[int]:
    status = capture.get("status_code")
    return status if isinstance(status, int) else None


def _headers_of(capture: Dict[str, Any]) -> Dict[str, str]:
    return {k.lower(): v for k, v in (capture.get("response_headers") or {}).items()}


def redirect_target(capture: Dict[str, Any]) -> Optional[str]:
    """Public wrapper for the redirect target of a capture."""
    return _redirect_target(capture)


def baseline_never_reached_app(capture: Dict[str, Any]) -> Optional[str]:
    """Return why the baseline response cannot be used as a reference, if so.

    A 3xx is served by routing, before any handler runs, and a 4xx/5xx block
    page is served in place of the application. Diffing a payload against
    either compares two different systems: the redirect that every request
    receives, and whatever answered the payload. Status and header deltas
    between them are properties of the CDN, not of the endpoint.
    """
    status = _status_of(capture)
    if status is None:
        return None
    if 300 <= status < 400:
        return (
            f"baseline response is a {status} redirect served before the "
            f"application ran; no endpoint logic was compared"
        )
    if status in (401, 407):
        return None
    if status in (403, 406, 429, 503):
        body = capture.get("response_body") or ""
        if _WAF_BLOCK_BODY.search(body) or _EDGE_RULE_MARKERS.search(body):
            return (
                f"baseline response is a {status} served by an edge defense, "
                f"not by the application under test"
            )
    return None


def edge_blocked(capture: Dict[str, Any]) -> Optional[str]:
    """Return why this capture looks like a rejected request, if it does."""
    body = capture.get("response_body") or ""
    headers = _headers_of(capture)
    marker = _EDGE_RULE_MARKERS.search(body)
    if marker or _WAF_BLOCK_BODY.search(body):
        detail = marker.group(0).strip() if marker else "edge block page"
        return f"response is an edge/WAF block page ({detail})"
    if headers.get("cf-mitigated") == "challenge":
        return "response is an edge/WAF challenge (cf-mitigated: challenge)"
    return None

# Volatile substrings that change on every response even when nothing about the
# request mattered. Differences confined to these are not evidence of anything.
# The value has to be consumed as well as the key, or two different nonces would
# still normalize to two different strings.
_VOLATILE = re.compile(
    r'"(?:timestamp|_ts|ts|nonce|csrf[_-]?token|request[_-]?id|trace[_-]?id)"'
    r'\s*:\s*"(?:[^"\\]|\\.)*"',
    re.IGNORECASE,
)


def _normalize_volatile(text: str) -> str:
    """Blank out values of fields that are expected to differ between responses."""
    return _VOLATILE.sub('""', text or "")


def scan_leaks(text: str) -> List[str]:
    """Return the names of sensitive value shapes present in ``text``."""
    if not text:
        return []
    found = []
    for name, pattern in _LEAK_PATTERNS.items():
        if pattern.search(text):
            found.append(name)
    return sorted(found)


def _first_divergence(a: str, b: str) -> int:
    limit = min(len(a), len(b))
    for i in range(limit):
        if a[i] != b[i]:
            return i
    return limit


def _body_delta(baseline_body: str, variant_body: str) -> Dict[str, Any]:
    """Describe how two bodies differ, ignoring expected volatile fields."""
    base_raw = baseline_body or ""
    var_raw = variant_body or ""

    identical_raw = base_raw == var_raw
    if identical_raw:
        return {"identical": True, "volatile_only": False, "summary": "bodies are byte-identical"}

    base_norm = _normalize_volatile(base_raw)
    var_norm = _normalize_volatile(var_raw)

    volatile_only = base_norm == var_norm
    if volatile_only:
        return {
            "identical": False,
            "volatile_only": True,
            "summary": "bodies differ only in expected volatile fields (timestamp/nonce/csrf); not evidence of a behaviour change",
        }

    offset = _first_divergence(base_norm, var_norm)
    base_leaks = set(scan_leaks(base_norm))
    var_leaks = set(scan_leaks(var_norm))
    newly_exposed = sorted(var_leaks - base_leaks)

    common_prefix = base_norm[:offset]
    tail = base_norm[max(0, len(base_norm) - (len(base_norm) - _common_suffix(base_norm, var_norm))):]

    if newly_exposed:
        summary = (
            f"variant response newly exposes {', '.join(newly_exposed)} "
            f"not present in baseline (first divergence at byte {offset})"
        )
    elif var_norm[:offset] == base_norm[:offset] and len(var_norm) != len(base_norm):
        summary = (
            f"variant body is a {len(var_norm) - len(base_norm):+d} byte variation "
            f"of the baseline (first divergence at byte {offset})"
        )
    else:
        summary = f"response content diverges from baseline at byte {offset}"

    return {
        "identical": False,
        "volatile_only": False,
        "summary": summary,
        "first_divergence_offset": offset,
        "baseline_length": len(base_raw),
        "variant_length": len(var_raw),
        "newly_exposed_patterns": newly_exposed,
        "common_prefix_length": len(common_prefix),
    }


def _common_suffix(a: str, b: str) -> int:
    limit = min(len(a), len(b))
    count = 0
    while count < limit and a[len(a) - 1 - count] == b[len(b) - 1 - count]:
        count += 1
    return count


def _header_delta(baseline_headers: Dict[str, str], variant_headers: Dict[str, str]) -> Dict[str, Any]:
    base = {k.lower(): v for k, v in (baseline_headers or {}).items()}
    var = {k.lower(): v for k, v in (variant_headers or {}).items()}

    added = {k: var[k] for k in var if k not in base}
    removed = {k: base[k] for k in base if k not in var}
    changed = {
        k: {"baseline": base[k], "variant": var[k]}
        for k in base
        if k in var and base[k] != var[k] and k in SECURITY_RELEVANT_HEADERS
    }

    security_added = {k: v for k, v in added.items() if k in SECURITY_RELEVANT_HEADERS}
    security_removed = {k: v for k, v in removed.items() if k in SECURITY_RELEVANT_HEADERS}

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "security_relevant_added": security_added,
        "security_relevant_removed": security_removed,
    }


def _redirect_target(capture: Dict[str, Any]) -> Optional[str]:
    """Where a response was actually served from, or None if it was not redirected.

    ``request_url`` is deliberately not a fallback. A differential variant is
    *supposed* to ask for a different URL, so treating the request URL as the
    "effective" one makes the two sides differ for every URL-borne comparison --
    which is every differential test worth running.
    """
    requested = capture.get("request_url")
    final = capture.get("final_url")
    if not requested or not final:
        return None
    return final if final != requested else None


def classify_differential(baseline: Dict[str, Any], variant: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two captures and report what changed, plus how much it matters.

    Returns a dict with ``material`` (bool) and ``signals`` (list of str). A
    difference only counts as material when something security-relevant moved:
    a status transition, a security header appearing or vanishing, a value
    shape that the baseline never exposed, or a body change that survives
    volatile-field normalization.

    A comparison that never reached the application is reported with
    ``material=False`` and ``blocked=<reason>``. A status change alone cannot
    distinguish a vulnerable endpoint from a working WAF: sending a payload to
    a Cloudflare-fronted host and getting a 403 where a plain request got a 301
    is the defense operating correctly, and scoring it material hands back a
    confirmed SQL injection for a site that blocked the injection.
    """
    baseline_blocked = baseline_never_reached_app(baseline)
    variant_blocked = edge_blocked(variant)

    if baseline_blocked or variant_blocked:
        reasons = [r for r in (baseline_blocked, variant_blocked) if r]
        return {
            "material": False,
            "blocked": True,
            "blocked_reasons": reasons,
            "inconclusive": True,
            "identical": False,
            "volatile_only": False,
            "signals": [
                "comparison inconclusive: " + "; ".join(reasons)
            ],
            "status": {
                "baseline": _status_of(baseline),
                "variant": _status_of(variant),
                "changed": _status_of(baseline) != _status_of(variant),
            },
            "headers": _header_delta(
                baseline.get("response_headers") or {},
                variant.get("response_headers") or {},
            ),
            "body": {"identical": False, "volatile_only": False, "summary": ""},
            "timing": {"baseline_ms": None, "variant_ms": None, "significant": False},
        }

    signals: List[str] = []

    base_status = baseline.get("status_code")
    var_status = variant.get("status_code")
    status_changed = base_status != var_status
    if status_changed:
        signals.append(f"status changed {base_status} -> {var_status}")

    base_headers = baseline.get("response_headers") or {}
    var_headers = variant.get("response_headers") or {}
    headers = _header_delta(base_headers, var_headers)

    if headers["security_relevant_added"]:
        names = ", ".join(sorted(headers["security_relevant_added"]))
        signals.append(f"security-relevant header(s) appeared in variant: {names}")
    if headers["security_relevant_removed"]:
        names = ", ".join(sorted(headers["security_relevant_removed"]))
        signals.append(f"security-relevant header(s) disappeared in variant: {names}")
    for name, pair in headers["changed"].items():
        signals.append(f"header '{name}' changed: {pair['baseline']!r} -> {pair['variant']!r}")

    body = _body_delta(baseline.get("response_body") or "", variant.get("response_body") or "")
    if body.get("newly_exposed_patterns"):
        signals.append(body["summary"])

    base_time = baseline.get("elapsed_ms")
    var_time = variant.get("elapsed_ms")
    timing_signal: Optional[str] = None
    if isinstance(base_time, (int, float)) and isinstance(var_time, (int, float)):
        delta = var_time - base_time
        if delta > TIMING_SIGNIFICANCE_MS:
            timing_signal = (
                f"variant took {delta:.0f}ms longer than baseline "
                f"({base_time}ms -> {var_time}ms)"
            )
            signals.append(timing_signal)

    # A redirect that only the variant triggers is a real authorization signal.
    # The target of the check is where the response *came from*, not where the
    # tester chose to send it: a differential variant requests a different URL
    # by construction, so falling back to the request URL made every URL-borne
    # comparison material and handed back a confirmation for simply appending a
    # payload. Only a genuine redirect -- a response served from somewhere other
    # than the URL that was requested -- counts, and only when it differs.
    base_redirect = _redirect_target(baseline)
    var_redirect = _redirect_target(variant)
    url_changed = base_redirect != var_redirect
    if url_changed and (base_redirect or var_redirect):
        signals.append(
            f"redirected: {base_redirect or 'none'} -> {var_redirect or 'none'}")

    volatile_only = bool(body.get("volatile_only"))
    identical = bool(body.get("identical")) and not status_changed and not (
        headers["security_relevant_added"] or headers["security_relevant_removed"] or headers["changed"]
    )

    # Content equivalence is what a plain re-render produces. A response can be
    # content-identical and still differ meaningfully, so a timing signal or a
    # change of effective URL keeps the comparison material even when every byte
    # of the body matches.
    content_equivalent = (
        (identical or (volatile_only and not status_changed))
        and not headers["security_relevant_added"]
        and not headers["security_relevant_removed"]
        and not headers["changed"]
        and not url_changed
    )
    material = bool(signals) and not (content_equivalent and timing_signal is None)

    return {
        "material": material,
        "blocked": False,
        "blocked_reasons": [],
        "inconclusive": False,
        "identical": identical,
        "volatile_only": volatile_only,
        "signals": signals,
        "status": {
            "baseline": base_status,
            "variant": var_status,
            "changed": status_changed,
        },
        "headers": headers,
        "body": body,
        "timing": {
            "baseline_ms": base_time,
            "variant_ms": var_time,
            "significant": timing_signal is not None,
        },
    }


def summarize_differential(result: Dict[str, Any]) -> str:
    """One-line human summary of a comparison, suitable for evidence."""
    if result.get("blocked"):
        reasons = "; ".join(result.get("blocked_reasons") or []) or "comparison did not reach the application"
        return f"inconclusive: {reasons}"
    if result.get("identical"):
        return "baseline and variant responses are equivalent; the change had no effect"
    if result.get("volatile_only") and not result.get("status", {}).get("changed"):
        return "responses differ only in expected volatile fields; the change had no material effect"
    signals = result.get("signals") or []
    if not signals:
        body = result.get("body") or {}
        return body.get("summary") or "no material difference observed"
    prefix = "material difference: " if result.get("material") else "difference: "
    return prefix + "; ".join(signals)
