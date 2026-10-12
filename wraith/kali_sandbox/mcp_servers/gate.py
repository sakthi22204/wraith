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
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

GRANT_VERSION = 1
KILLSWITCH_KEY = "global:killswitch"

# Spent-grant nonces. Keyed per investigation so two grants that collide on a
# nonce value stay independent. Entries expire with the grants they describe;
# there is no cleanup here because a stale entry is indistinguishable from a
# spent one, which is the safe direction.
NONCE_KEY_PREFIX = "gate:spent_nonce"

# Tools the exploit agent may authorise with a grant it mints itself. The
# agent's dispatch layer only issues grants for these, and this floor is
# re-checked here rather than trusted from the mint: a compromise that turns
# the agent into an arbitrary grant-minter still cannot widen this list,
# because the sandbox refuses to honour an exploit_agent grant for anything
# else. Everything that sends exploit payloads (dalfox, xsstrike, jwt_tool,
# commix, ghauri, sqlmap, hydra, msf) stays behind the runner's
# approve-to-dispatch, where a human approves each submission.
EXPLOIT_AGENT_READ_ONLY_TOOLS = frozenset({
    "run_nmap_scan", "run_nuclei_scan", "run_arjun", "run_corsy", "run_nikto",
})


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
    """The bare hostname of a destination, or "" if none can be read.

    A bare host is accepted, because that is what nmap, nuclei and hydra are
    given. `urlparse("juice_shop").hostname` is None -- there is no scheme, so
    there is no netloc -- which made every port-selecting tool unresolvable and
    the request refused. That fails closed, so it was not a bypass, but it meant
    the port work could never be exercised against a real bare-host target, and
    a refusal that looks like "host not in scope" misreports the actual problem.
    """
    candidate = (url or "").strip()
    if not candidate:
        return ""
    if "://" not in candidate:
        if not BARE_HOST_RE.match(candidate):
            # Not a bare `host` or `host:port`. Prefixing a scheme would make
            # urlparse treat prose as a hostname -- "not a url" became the host
            # "not a url" -- and a destination nobody could have meant has to
            # read as undeterminable rather than as a scope miss.
            return ""
        candidate = "http://" + candidate
    try:
        return (urlparse(candidate).hostname or "").lower()
    except Exception:  # noqa: BLE001
        return ""


DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# A port claim wider than this is refused. nmap's own default is "1-1000"; past
# a few thousand the claim has stopped describing a decision anyone made and
# started being a licence for the whole host, which is what binding the port was
# meant to prevent.
MAX_CLAIMED_PORTS = 4096

# What a destination may look like when it carries no scheme -- what nmap,
# nuclei and hydra are handed. Deliberately narrow: a label (letters, digits,
# dots, hyphens, underscores), optionally one colon and digits. Anything else is
# prose, a path, or a URL with its scheme stripped, and is refused as
# undeterminable rather than guessed at.
BARE_HOST_RE = re.compile(r"^[A-Za-z0-9._-]+(:[0-9]{1,5})?$")


def port_of(url: str) -> Optional[int]:
    """The port a URL will actually be dialled on, or None if unreadable."""
    try:
        parsed = urlparse(url)
        if parsed.port is not None:
            return parsed.port
        return DEFAULT_PORTS.get((parsed.scheme or "").lower())
    except Exception:  # noqa: BLE001
        return None


def parse_port_spec(spec) -> set:
    """Expand a port claim like ``80``, ``80,443`` or ``1-1000`` to a set of ints.

    Fails closed on anything malformed, on an empty claim, and on a claim wide
    enough to be a disguised allow-everything. Mirrors
    ``active_exploit_runner/app/roe/authority.py::normalize_port_claim``; both
    are pinned to the same vectors in ``tests/test_grant_port_claim.py`` so the
    two encodings cannot drift.
    """
    if spec is None or (isinstance(spec, str) and not spec.strip()):
        raise GateError("port claim is empty; refusing to send", 403)
    ports: set = set()
    try:
        if isinstance(spec, (list, tuple, set)):
            parts = [str(p) for p in spec]
        elif isinstance(spec, int) and not isinstance(spec, bool):
            parts = [str(spec)]
        elif isinstance(spec, str):
            parts = spec.split(",")
        else:
            raise ValueError(f"not a port claim: {spec!r}")
    except (TypeError, ValueError) as exc:
        raise GateError(f"port claim {spec!r} is malformed; refusing to send", 403) from exc

    for part in parts:
        part = str(part).strip()
        if not part:
            raise GateError(f"port claim {spec!r} is malformed; refusing to send", 403)
        if "-" in part:
            lo_raw, _, hi_raw = part.partition("-")
            if not (lo_raw.strip().isdigit() and hi_raw.strip().isdigit()):
                raise GateError(f"port range {part!r} is malformed; refusing to send", 403)
            lo, hi = int(lo_raw), int(hi_raw)
            if lo > hi:
                raise GateError(f"port range {part!r} is inverted; refusing to send", 403)
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise GateError(f"port range {part!r} is outside 1-65535; refusing to send", 403)
            if hi - lo + 1 > MAX_CLAIMED_PORTS:
                raise GateError(
                    f"port claim {spec!r} covers {hi - lo + 1} ports, more than the "
                    f"{MAX_CLAIMED_PORTS} this gate will honour; refusing to send", 403)
            ports.update(range(lo, hi + 1))
        else:
            if not part.isdigit():
                raise GateError(f"port {part!r} is malformed; refusing to send", 403)
            value = int(part)
            if not 1 <= value <= 65535:
                raise GateError(f"port {value} is outside 1-65535; refusing to send", 403)
            ports.add(value)
    if not ports:
        raise GateError(f"port claim {spec!r} names no ports; refusing to send", 403)
    return ports


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

    A bare host with no scheme -- what nmap, nuclei and hydra take -- resolves to
    that host on port 80, which is what such a tool means by an unported host.
    """
    candidate = (url or "").strip()
    try:
        parsed = urlparse(candidate if "://" in candidate else "http://" + candidate)
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


def _redis_client(redis_url: str):
    import redis as redis_lib

    return redis_lib.Redis.from_url(redis_url, socket_timeout=3)


def spend_nonce(token: str, settings, *, now: Optional[float] = None) -> bool:
    """Record a grant's nonce as spent, refusing one that has been used before.

    Runs after verification, so an unsigned or expired token never reaches the
    store -- otherwise an attacker who merely *saw* a grant could burn it by
    replaying it, turning single-use into denial of service.

    Fails closed. "Have I seen this nonce?" cannot be answered without the shared
    store, and an unreachable Redis during an incident is exactly when an
    attacker would replay. The key includes the investigation, so two grants that
    happen to share a nonce stay independent.
    """
    # Raises GateError on a bad signature or an expired token, before any store
    # access.
    payload = verify_grant(token, settings.GATE_SECRET, now=now)

    redis_url = getattr(settings, "REDIS_URL", "")
    if not redis_url:
        raise GateError("no Redis configured; cannot confirm a grant is unused", 500)

    key = f"{NONCE_KEY_PREFIX}:{payload.get('inv')}"
    try:
        client = _redis_client(redis_url)
        # sadd() returns 0 when the member is already present, which is the
        # single-use check and the record in one atomic operation.
        added = client.sadd(key, str(payload.get("nonce")))
    except GateError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise GateError(
            f"grant replay store unavailable ({type(exc).__name__}); refusing", 500
        ) from exc

    if not added:
        raise GateError("this grant has already been used", 403)
    return True


def _check_destination(url: str, *, granted_host: str, rules: List[Dict[str, str]],
                       investigation_id: str, port_claim: Optional[str] = None,
                       granted_ports: Optional[set] = None) -> None:
    """Every condition a single destination has to clear. Raises to refuse.

    ``port_claim`` is the set of ports the *request* will dial;
    ``granted_ports`` is the set the *grant* authorised. Both are needed and they
    are different claims -- the previous version derived the granted set from the
    request, so a request for ``1-65535`` was checked against itself and always
    passed. A port is authorised only when the tool will dial it *and* the grant
    named it.
    """
    host = host_of(url)
    if not host:
        raise GateError(f"could not determine destination host from '{url}'", 403)
    # Compared as host:port, so a grant for one destination cannot be spent
    # on another port of the same host. Scope matching still uses the bare
    # hostname, because that is what an investigation's rules are written
    # against.
    authority = authority_of(url)

    granted_host_name = granted_host.split(":")[0]
    if host != granted_host_name:
        raise GateError(
            f"grant is for '{granted_host}', refusing request to '{authority}'", 403)

    requested_ports = parse_port_spec(port_claim) if port_claim is not None else None
    if requested_ports is not None:
        # A tool that chooses its own ports names the host, not an authority, so
        # the host is settled above and only the port set is left to compare.
        if granted_ports is None:
            # The grant named no port set, so it authorises exactly the one port
            # its own authority carries. A tool that sweeps ports is asking for
            # more than that.
            allowed = {int(granted_host.rpartition(":")[2])} if ":" in granted_host else set()
        else:
            allowed = granted_ports
        outside = sorted(requested_ports - allowed)
        if outside:
            raise GateError(
                f"grant '{granted_host}' authorises ports "
                f"{sorted(allowed) or 'none'}; the request would dial "
                f"{outside[:8]}{'...' if len(outside) > 8 else ''}; refusing to send",
                403)
    elif authority != granted_host:
        raise GateError(
            f"grant is for '{granted_host}', refusing request to '{authority}'", 403)

    if not is_in_scope(rules, host) and not is_in_scope(rules, url):
        raise GateError(
            f"host '{host}' does not match any allow rule for investigation "
            f"'{investigation_id}'", 403)


def _check_tool(grant_tools: Optional[List[str]], caller: str, tool: Optional[str]) -> None:
    """The tool a grant authorises, checked against the call it is spent on.

    A grant carrying a ``tools`` list may only be spent on those tools; a grant
    without one predates the claim and stays unrestricted. Either way the caller
    floor applies: ``exploit_agent`` grants are only honoured for the read-only
    set, so a compromised agent cannot widen a grant it has already minted.
    """
    if caller == "exploit_agent":
        if tool not in EXPLOIT_AGENT_READ_ONLY_TOOLS:
            raise GateError(
                f"caller 'exploit_agent' may only authorise "
                f"{sorted(EXPLOIT_AGENT_READ_ONLY_TOOLS)}; got '{
                    tool}'; refusing to send", 403)
    if grant_tools and tool not in grant_tools:
        raise GateError(
            f"grant authorises {sorted(grant_tools)}; the call is for '{tool}'; "
            f"refusing to send", 403)


def authorization_context(
    *,
    caller: Optional[str],
    grant_token: Optional[str],
    targets: List[str],
    settings,
    port_claim: Optional[str] = None,
    tool: Optional[str] = None,
) -> Dict[str, Any]:
    """Run every gate for a set of destinations and return the reusable context.

    A redirect is followed *after* this returns, by code that does not know about
    grants, so the checks a later hop needs are kept here: the verified grant's
    host and the investigation's scope rules. ``revalidate_hop`` then applies the
    same conditions to each new destination, which is what stops a 302 from
    becoming an off-scope fetch.
    """
    if killswitch_active(settings.REDIS_URL):
        raise GateError("global killswitch is active; sandbox refused to send", 403)

    secret = settings.GATE_SECRET
    payload = verify_grant(grant_token, secret)
    if payload.get("caller") != caller:
        raise GateError(
            f"grant was issued to '{payload.get('caller')}' but the caller claims '{caller}'", 403)

    _check_tool(payload.get("tools"), caller, tool)

    investigation_id = payload.get("inv")
    granted_host = (payload.get("host") or "").lower()
    if not investigation_id or not granted_host:
        raise GateError("grant does not name an investigation and host", 403)

    rules = load_scope_rules(settings.DATABASE_URL, investigation_id)
    if not rules:
        raise GateError(
            f"investigation '{investigation_id}' has no scope rules; refusing to send", 403)

    # The grant's own port claim, if it named one. Absent means "the single port
    # in the authority", which is the pre-claim behaviour and the tighter of the
    # two -- so an old grant cannot widen what it authorises.
    granted_ports = None
    if payload.get("ports") is not None:
        try:
            granted_ports = parse_port_spec(payload["ports"])
        except GateError as exc:
            # A grant naming an unreadable port set is not a grant this gate can
            # honour. Refusing beats silently falling back to the authority's
            # single port, which would look like a narrower grant than the runner
            # believes it issued.
            raise GateError(
                f"grant's port claim is unusable ({exc.detail}); refusing to send", 403)

    # The grant is verified and in scope by this point, so it is safe to burn.
    # After this line the nonce is spent whether or not the remaining destination
    # checks pass -- deliberate, so a rejected request cannot be retried with the
    # same grant against a corrected body.
    spend_nonce(grant_token, settings)

    for url in targets:
        _check_destination(url, granted_host=granted_host, rules=rules,
                           investigation_id=investigation_id, port_claim=port_claim,
                           granted_ports=granted_ports)

    return {
        "investigation_id": investigation_id,
        "host": granted_host,
        "granted_host": granted_host,
        "granted_ports": sorted(granted_ports) if granted_ports else None,
        "port_claim": port_claim,
        "rules": rules,
        "cost": int(payload.get("cost", 1)),
        "expires_at": payload.get("exp"),
    }


def revalidate_hop(context: Dict[str, Any], url: str) -> None:
    """Apply the gate's conditions to a redirect hop. Raises GateError to refuse.

    Deliberately does not re-verify the signature or spend the nonce: the grant
    was verified once when the context was built, and one grant covers the whole
    redirect chain. It does re-read the rules held in the context rather than
    assuming the new host inherits the old one's verdict.
    """
    granted_ports = context.get("granted_ports")
    _check_destination(
        url,
        granted_host=context["granted_host"],
        rules=context["rules"],
        investigation_id=context["investigation_id"],
        port_claim=context.get("port_claim"),
        granted_ports=set(granted_ports) if granted_ports else None,
    )


def enforce(
    *,
    caller: Optional[str],
    grant_token: Optional[str],
    targets: List[str],
    settings,
    port_claim: Optional[str] = None,
    tool: Optional[str] = None,
) -> Dict[str, Any]:
    """Run every gate for a set of destination URLs. Raises GateError to refuse.

    ``targets`` is every URL that will actually be sent, so a variant that
    points somewhere else is checked on its own account rather than riding in
    on the baseline's authorisation.

    ``port_claim`` is for tools that dial a port the request chose rather than
    one the URL named -- nmap's ``-p 1-1000``, nuclei against a whole host. For
    those, a grant naming ``host:80`` would silently authorise all 1000 ports,
    which is the exact over-grant the authority binding exists to prevent. The
    claim is compared against the grant's own ``ports`` field instead, so the
    authority stays meaningful: a grant for ``1-1000`` cannot be spent on 22.

    ``tool`` names the sandbox tool the grant will be spent on. It stays
    optional so pre-tool-scoping callers keep working, and so an SSE call with
    no grant at all is still refused the same way it always was.
    """
    return authorization_context(
        caller=caller,
        grant_token=grant_token,
        targets=targets,
        settings=settings,
        port_claim=port_claim,
        tool=tool,
    )