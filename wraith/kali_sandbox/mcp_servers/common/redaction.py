"""Redaction helpers for validation evidence.

Validation records capture raw HTTP traffic so a human can replay a finding.
That same capture is a credential-leak risk: replay evidence routinely carries
session cookies, bearer tokens, and unrelated PII pulled in by the request or
echoed back by the target.

Redaction is applied on the way IN, before anything is persisted or rendered, so
an unredacted value never reaches the graph, the audit log, or a report.
"""
import re
from typing import Any, Dict, Iterable, List, Tuple

REDACTED = "[REDACTED]"

# Header names whose values are secret. Matched case-insensitively on the
# header name, not the value, so we never have to guess a value's format.
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-goog-api-key",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
})

# A WWW-Authenticate value is a challenge, not a credential: it names the scheme
# and usually a realm or error code, which is exactly what an analyst needs to
# tell how to authenticate. Masking it wholesale hides that while protecting
# nothing -- the credential lives in the request's Authorization header. It is
# scrubbed selectively instead, so a server that echoes a token or secret into
# the challenge still cannot leak one through the evidence.
CHALLENGE_HEADER = "www-authenticate"

# Anything long and opaque is treated as a credential even inside a challenge.
_CHALLENGE_CREDENTIAL = re.compile(
    r"(?i)\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"   # JWT
    r"|[A-Fa-f0-9]{24,}"                                                  # long hex
    r"|[A-Za-z0-9+/=_-]{40,})"                                             # long opaque
)


def scrub_auth_challenge(value: str) -> str:
    """Keep the scheme and error codes, mask credential-shaped values."""
    if not isinstance(value, str) or not value:
        return value
    return _CHALLENGE_CREDENTIAL.sub(REDACTED, value)

# Value-shaped secrets. These are deliberately conservative: too greedy a rule
# destroys reproducibility by mangling the very request we want replayable.
_VALUE_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    # JSON web tokens
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    # vendor token prefixes
    ("api_key", re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    # key=value / key: value inside query strings, headers, bodies
    ("assignment", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|"
        r"refresh[_-]?token|client[_-]?secret|session[_-]?id|auth)\b"
        r"(\s*[=:]\s*|%3D)([^\s&;\"',<>}\]]+)"
    )),
)

# Body fields that are user PII in a generic web app. Key-name based so we do
# not need to know the application's schema.
PII_BODY_FIELDS = (
    "email", "e-mail", "mail", "password", "passwd", "pwd",
    "ssn", "socialsecuritynumber", "creditcard", "cardnumber", "cvv", "cvc",
    "phonenumber", "phone", "dob", "dateofbirth", "address", "zip", "postalcode",
)


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Replace sensitive header values wholesale.

    One exception: a ``WWW-Authenticate`` challenge names the auth scheme and
    realm an analyst needs to proceed. It is scrubbed selectively rather than
    masked, so a server echoing a credential into the challenge still cannot
    leak one through the evidence.
    """
    out: Dict[str, str] = {}
    for name, value in (headers or {}).items():
        lowered = str(name).lower()
        if lowered == CHALLENGE_HEADER:
            out[name] = scrub_auth_challenge(value)
        elif lowered in ("cookie", "set-cookie"):
            # Keep the cookie NAME so an analyst can see which cookie the
            # target set (session, CSRF, analytics...); mask its value.
            out[name] = scrub_set_cookie(value) if lowered == "set-cookie" else scrub_cookie_header(value)
        elif lowered in SENSITIVE_HEADERS:
            out[name] = REDACTED
        else:
            out[name] = value
    return out


_SAFE_COOKIE_ATTRS = {
    "path", "domain", "expires", "max-age", "secure",
    "httponly", "samesite", "priority", "partitioned", "comment",
}


def _mask_cookie_pairs(value: str, preserve_attrs: bool) -> str:
    """Mask cookie values; keep names, and attribute values when safe."""
    if not isinstance(value, str) or not value:
        return value
    parts = []
    for token in value.split(";"):
        token = token.strip()
        if not token or "=" not in token:
            parts.append(token)
            continue
        key, _sep, val = token.partition("=")
        if preserve_attrs and key.strip().lower() in _SAFE_COOKIE_ATTRS:
            parts.append(token)
        else:
            parts.append(f"{key}={REDACTED}")
    return "; ".join(parts)


def scrub_cookie_header(value: str) -> str:
    """A request Cookie's every value is a credential; mask all of them."""
    return _mask_cookie_pairs(value, preserve_attrs=False)


def scrub_set_cookie(value: str) -> str:
    """A Set-Cookie keeps its cookie name and non-secret attributes.

    ``set-cookie: session=xyz; Path=/; HttpOnly`` becomes
    ``set-cookie: session=[REDACTED]; Path=/; HttpOnly``. The name and flags an
    analyst needs to reason about are preserved; the value that would be stolen
    is not.
    """
    return _mask_cookie_pairs(value, preserve_attrs=True)



def redact_text(text: str) -> str:
    """Mask secret-shaped substrings in free text (bodies, query strings)."""
    if not text:
        return text
    result = text
    for _name, pattern in _VALUE_PATTERNS:
        if _name == "assignment":
            # Preserve the key so the reader can see WHICH field was secret.
            result = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", result)
        else:
            result = pattern.sub(REDACTED, result)
    return result


def redact_body(body: Any, content_type: str = "") -> Any:
    """Redact a response body, structure-aware for JSON."""
    if body is None:
        return body
    ctype = (content_type or "").lower()

    if isinstance(body, (dict, list)):
        return _redact_json(body)
    if not isinstance(body, str):
        return body

    stripped = body.lstrip()
    if "json" in ctype or stripped[:1] in ("{", "["):
        # Sniff by shape too: callers frequently omit or mis-set Content-Type,
        # and a JSON body in a text/plain request is still a JSON body.
        import json
        try:
            return _redact_json(json.loads(body))
        except (ValueError, TypeError):
            pass
    if "form-urlencoded" in ctype:
        return _redact_query_string(body)
    return redact_text(body)


def _redact_json(node: Any) -> Any:
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if str(key).lower() in PII_BODY_FIELDS or str(key).lower().replace("-", "") in {
                f.replace("-", "") for f in PII_BODY_FIELDS
            }:
                out[key] = REDACTED
            else:
                out[key] = _redact_json(value)
        return out
    if isinstance(node, list):
        return [_redact_json(v) for v in node]
    if isinstance(node, str):
        return redact_text(node)
    return node


def _redact_query_string(text: str) -> str:
    import urllib.parse
    try:
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True)
    except ValueError:
        return redact_text(text)
    lowered = {f.replace("-", "") for f in PII_BODY_FIELDS}
    out = []
    for key, value in pairs:
        if key.lower() in PII_BODY_FIELDS or key.lower().replace("-", "") in lowered:
            value = REDACTED
        else:
            value = redact_text(value)
        out.append(f"{key}={value}")
    return "&".join(out)


def redact_url(url: str) -> str:
    """Redact a URL's query values and any embedded userinfo credentials.

    URLs are the one place a secret routinely hides without looking like one:
    `?token=...`, `?sig=...`, `?access_token=...` are all plaintext in the
    evidence even though the same value in a body would be caught. Because the
    captured request has to stay replayable, the KEY is preserved and only the
    value is masked, so a reader can still see which parameter carried a secret.

    Userinfo (`https://user:pass@host`) is reduced to the host alone.
    """
    if not url or not isinstance(url, str):
        return url
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return redact_text(url)

    if not parsed.scheme and not parsed.netloc:
        # Relative or malformed; fall back to the text rules.
        return redact_text(url)

    netloc = parsed.netloc
    if "@" in netloc:
        # Drop the user:password portion entirely.
        netloc = netloc.rsplit("@", 1)[1]

    query = ""
    if parsed.query:
        try:
            pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        except ValueError:
            query = REDACTED
        else:
            lowered = {f.replace("-", "") for f in PII_BODY_FIELDS}
            rendered = []
            for key, value in pairs:
                key_norm = key.lower()
                if key_norm in PII_BODY_FIELDS or key_norm.replace("-", "") in lowered:
                    value = REDACTED
                else:
                    # Catches vendor-token shapes and key=value forms that the
                    # PII list does not name.
                    value = redact_text(value)
                rendered.append(f"{key}={value}")
            query = "&".join(rendered)

    try:
        return urllib.parse.urlunsplit(
            (parsed.scheme, netloc, parsed.path, query, parsed.fragment)
        )
    except ValueError:
        return redact_text(url)


def redact_capture(capture: Dict[str, Any]) -> Dict[str, Any]:
    """Redact a full probe capture in place-safe fashion (returns a new dict)."""
    redacted: Dict[str, Any] = dict(capture)
    if "request_headers" in redacted:
        redacted["request_headers"] = redact_headers(redacted["request_headers"] or {})
    if "response_headers" in redacted:
        redacted["response_headers"] = redact_headers(redacted["response_headers"] or {})

    # URLs carry secrets in the query string, so they are redacted on the same
    # path as the rest of the capture -- before anything is persisted.
    for url_field in ("request_url", "final_url"):
        if url_field in redacted:
            redacted[url_field] = redact_url(redacted[url_field])
    if isinstance(redacted.get("redirects"), list):
        redacted["redirects"] = [
            redact_url(u) if isinstance(u, str) else u for u in redacted["redirects"]
        ]

    # Request bodies are redacted too: an agent-authored PoC routinely carries
    # test credentials, and the captured request is stored as evidence.
    # The request's own Content-Type is only a hint, and the agent does not
    # always set it correctly, so JSON is also detected by shape.
    req_ct = ""
    for name, value in (redacted.get("request_headers") or {}).items():
        if str(name).lower() == "content-type":
            req_ct = str(value)
            break
    if "request_body" in redacted:
        redacted["request_body"] = redact_body(redacted["request_body"], req_ct)

    if "response_body" in redacted:
        redacted["response_body"] = redact_body(
            redacted["response_body"],
            (redacted.get("response_headers") or {}).get("content-type", ""),
        )
    return redacted
