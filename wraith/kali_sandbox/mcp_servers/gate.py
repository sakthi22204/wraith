"""Gate enforcement for the sandbox's own network-facing tools.

``active_exploit_runner`` checks killswitch, ROE and rate limit before it calls
this service, but those checks lived only in the caller. A caller header is
just a string, so anything able to reach this port could skip the gates
entirely. Enforcement therefore happens here as well, on three independent
conditions, each of which fails closed:

1. the global killswitch, read from Redis;
2. a signed, unexpired grant that names the caller, the investigation and the
   exact host the request is for;
3. the investigation's own scope rules, re-read from the database.

A request that clears all three is one the runner already authorised.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

GRANT_VERSION = 1
KILLSWITCH_KEY = "global:killswitch"


class GateError(Exception):
    """Refused before any packet was sent. Carries an HTTP status."""

    def __init__(self, detail: str, status_code: int = 403):
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_grant(token: str, secret: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Return the grant payload, or raise GateError. Mirrors the runner's mint."""
    if not secret:
        raise GateError("gate secret is not configured; refusing to trust any grant", 500)
    if not token or not isinstance(token, str) or token.count(".") != 1:
        raise GateError("malformed or missing grant", 403)
    body_b64, sig_b64 = token.split(".")
    try:
        body = _b64d(body_b64)
        signature = _b64d(sig_b64)
    except Exception as exc:  # noqa: BLE001
        raise GateError("malformed grant encoding", 403) from exc

    expected = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise GateError("grant signature is not valid for this gate secret", 403)
    try:
        payload = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        raise GateError("grant payload is not readable", 403) from exc
    if not isinstance(payload, dict) or payload.get("v") != GRANT_VERSION:
        raise GateError("unsupported grant version", 403)
    if int(payload.get("exp", 0)) < int(now if now is not None else time.time()):
        raise GateError("grant has expired", 403)
    return payload


def _specificity(pattern: str) -> tuple:
    """Mirror of the runner's ordering: a literal beats a wildcard beats '*'."""
    p = pattern.strip()
    if p == "*":
        return (0,)
    if p.startswith("*.") or p.endswith(".*"):
        return (1, p.replace("*.", "").replace(".*", ""))
    return (2, p)


def _match(pattern: str, target: str) -> bool:
    from fnmatch import fnmatch
    p, t = pattern.strip().lower(), (target or "").lower()
    if p == "*":
        return True
    if p.startswith("*."):
        suffix = p[1:]  # ".example.com"
        return t == p[2:] or t.endswith(suffix)
    if "/" in p and not p.startswith("*") and ":" not in p:
        import ipaddress
        try:
            net = ipaddress.ip_network(p, strict=False)
            return ipaddress.ip_address(t) in net
        except ValueError:
            return False
    return fnmatch(t, p) or t == p


def is_in_scope(rules: List[Dict[str, str]], target: str) -> bool:
    """Most specific matching rule decides; deny wins ties; no match is denied."""
    best_spec, best_is_deny = None, False
    for rule in rules:
        if not _match(rule["pattern"], target):
            continue
        spec = _specificity(rule["pattern"])
        rule_is_deny = str(rule.get("rule_type", "")).lower().endswith("deny")
        if best_spec is None or spec > best_spec:
            best_spec, best_is_deny = spec, rule_is_deny
        elif spec == best_spec and rule_is_deny:
            best_is_deny = True
    return best_spec is not None and not best_is_deny


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}


def authority_of(url: str) -> str:
    """``host:port`` for a URL, with the scheme's default port filled in.

    The grant used to bind a bare hostname, which was adequate while every tool
    spoke HTTP to the port its own URL named. A raw-socket tool is different: it
    chooses the port it dials, so a grant for ``example.com:80`` would silently
    authorise ``example.com:22`` and every other port on that host. Binding the
    port too keeps the grant meaning "this exact destination", which is the
    whole reason it exists.

    Normalising the default port is what makes this safe to compare: a URL that
    omits the port and a URL that spells out ``:80`` are the same destination,
    and must produce the same string on both sides of the check.
    """
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            return ""
        port = parsed.port
        if port is None:
            port = DEFAULT_PORTS.get((parsed.scheme or "").lower())
        # A bracketed IPv6 literal must stay bracketed to remain a valid
        # authority, and ':' in the host would otherwise be ambiguous.
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{host}:{port}" if port else host
    except Exception:  # noqa: BLE001
        return ""


def killswitch_active(redis_url: str) -> bool:
    """Read the global stop control. An unreachable Redis fails closed."""
    if not redis_url:
        raise GateError("no Redis configured; cannot confirm killswitch state", 500)
    try:
        import redis as redis_lib
    except ImportError as exc:
        raise GateError(
            "redis client is not installed; cannot confirm killswitch state, refusing", 500
        ) from exc
    try:
        return redis_lib.Redis.from_url(redis_url, socket_timeout=3).get(KILLSWITCH_KEY) == b"active"
    except Exception as exc:  # noqa: BLE001
        raise GateError(f"killswitch state unavailable ({type(exc).__name__}); refusing", 500) from exc


def load_scope_rules(database_url: str, investigation_id: str) -> List[Dict[str, str]]:
    if not database_url:
        raise GateError("no database configured; cannot confirm scope", 500)
    try:
        from sqlalchemy import create_engine, text
        engine = create_engine(database_url, pool_pre_ping=True)
        with engine.connect() as conn:
            rows = conn.execute(
                text("SELECT pattern, rule_type FROM scope_rules WHERE investigation_id = :inv"),
                {"inv": investigation_id},
            ).fetchall()
        return [{"pattern": r[0], "rule_type": r[1]} for r in rows]
    except GateError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise GateError(f"scope rules unavailable ({type(exc).__name__}); refusing", 500) from exc


def enforce(
    *,
    caller: Optional[str],
    grant_token: Optional[str],
    targets: List[str],
    settings,
) -> Dict[str, Any]:
    """Run every gate for a set of destination URLs. Raises GateError to refuse.

    ``targets`` is every URL that will actually be sent, so a variant that
    points somewhere else is checked on its own account rather than riding in
    on the baseline's authorisation.
    """
    if killswitch_active(settings.REDIS_URL):
        raise GateError("global killswitch is active; sandbox refused to send", 403)

    secret = settings.GATE_SECRET
    payload = verify_grant(grant_token, secret)
    if payload.get("caller") != caller:
        raise GateError(
            f"grant was issued to '{payload.get('caller')}' but the caller claims '{caller}'", 403)

    investigation_id = payload.get("inv")
    granted_host = (payload.get("host") or "").lower()
    if not investigation_id or not granted_host:
        raise GateError("grant does not name an investigation and host", 403)

    rules = load_scope_rules(settings.DATABASE_URL, investigation_id)
    if not rules:
        raise GateError(
            f"investigation '{investigation_id}' has no scope rules; refusing to send", 403)

    for url in targets:
        host = host_of(url)
        if not host:
            raise GateError(f"could not determine destination host from '{url}'", 403)
        # Compared as host:port, so a grant for one destination cannot be spent
        # on another port of the same host. Scope matching still uses the bare
        # hostname, because that is what an investigation's rules are written
        # against.
        authority = authority_of(url)
        if authority != granted_host:
            raise GateError(
                f"grant is for '{granted_host}', refusing request to '{authority}'", 403)
        if not is_in_scope(rules, host) and not is_in_scope(rules, url):
            raise GateError(
                f"host '{host}' does not match any allow rule for investigation "
                f"'{investigation_id}'", 403)

    return {"investigation_id": investigation_id, "host": granted_host,
            "cost": int(payload.get("cost", 1)), "expires_at": payload.get("exp")}