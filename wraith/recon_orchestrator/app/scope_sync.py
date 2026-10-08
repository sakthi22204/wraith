"""Reconcile the two records of what an investigation is allowed to touch.

There are deliberately two copies of scope:

* ``investigation.scope_domains`` in graph_db, which says what the operator
  asked to be scanned. This is the *selection* record.
* ``scope_rules`` in the active runner's postgres, which the runner and the
  sandbox re-read independently before anything is sent. This is the
  *enforcement* record.

The enforcement copy stays independent on purpose -- a graph compromise must not
be able to widen what the runner will send -- so the duplication cannot be
removed by pointing one at the other. What was missing is a check that the two
agree. When they disagree, recon happily selects targets the runner would
refuse, or refuses targets the operator scoped, and the only symptom is a
rejected session whose error does not say which record was wrong.

This module makes the divergence explicit and fails closed: every domain in the
selection record must also be covered by the enforcement record before a scan
starts.
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx
import ipaddress


class ScopeReconciliationError(RuntimeError):
    """The selection scope is not fully covered by the enforced scope."""

    def __init__(self, unauthorized: List[str], graph_scope: List[str], roe_scope: List[str]):
        self.unauthorized = unauthorized
        self.graph_scope = graph_scope
        self.roe_scope = roe_scope
        super().__init__(
            f"scope reconciliation failed: {len(unauthorized)} domain(s) in the "
            f"investigation's scope are not covered by any active-exploit-runner "
            f"ROE rule: {', '.join(unauthorized)}. Recon would select them and the "
            f"runner would then refuse them. Add a ROE rule for each "
            f"(POST /api/v1/roe/scope) or correct investigation.scope_domains. "
            f"graph={graph_scope or '[]'} roe={roe_scope or '[]'}"
        )


@dataclass
class ScopeReconciliation:
    graph_scope: List[str] = field(default_factory=list)
    roe_scope: List[str] = field(default_factory=list)
    unauthorized: List[str] = field(default_factory=list)
    roe_unavailable: bool = False

    @property
    def agreed(self) -> bool:
        return not self.unauthorized and not self.roe_unavailable


def extract_roe_patterns(payload: Any) -> List[str]:
    """Pull the pattern strings out of a ``GET /roe/scope/{id}`` response.

    The route serializes ORM rows, so the shape depends on the install; accept a
    bare list of strings as well as a list of dicts rather than assuming one.
    """
    rules = extract_roe_rules(payload)
    out: List[str] = []
    for rule in rules:
        pattern = rule.get("pattern") or rule.get("value") or rule.get("domain")
        if isinstance(pattern, str) and pattern:
            out.append(pattern)
    return out


def extract_roe_rules(payload: Any) -> List[Dict[str, Any]]:
    """Pull the rule objects out of a ``GET /roe/scope/{id}`` response.

    Normalized to ``{"pattern", "rule_type", "allow_aggressive"}`` so a caller
    can read the enforcement decision per rule (not just the patterns, which
    express the host range without the policy attached to it).
    """
    if payload is None:
        return []
    if isinstance(payload, dict):
        for key in ("rules", "scope", "items", "results", "data"):
            if key in payload:
                return extract_roe_rules(payload[key])
        # A single serialized rule object, not a wrapper.
        if "pattern" in payload or "value" in payload:
            return [payload]
        return []
    if not isinstance(payload, list):
        return []
    rules: List[Dict[str, Any]] = []
    for item in payload:
        if isinstance(item, str):
            # A bare pattern string is a legacy rule representation: an allow
            # rule whose pattern is the string itself and no policy attached.
            if item:
                rules.append({
                    "pattern": item,
                    "rule_type": "allow",
                    "allow_aggressive": False,
                })
            continue
        if not isinstance(item, dict):
            continue
        rule_type = item.get("rule_type") or item.get("action") or "allow"
        allow = item.get("allow_aggressive")
        rules.append({
            "pattern": item.get("pattern") or item.get("value") or item.get("domain"),
            "rule_type": rule_type,
            "allow_aggressive": bool(allow) if allow is not None else False,
        })
    return rules


def _scope_host(value: str) -> str:
    """Reduce a scope entry to the host the runner will actually match on.

    The runner decides scope on the destination host: ``host_of`` in
    ``app/validation.py`` runs the URL through ``urlparse().hostname``, which
    drops the port. So the rule ``juice_shop`` already authorizes
    ``http://juice_shop:3000/...`` -- a bare rule covers every port on the host.

    Comparing the two records with the port still attached makes reconciliation
    report a disagreement the enforcement record does not have: on the Juice Shop
    E2E, graph scope ``juice_shop:3000`` against ROE rule ``juice_shop`` was
    rejected with a 400, so recon refused to start and every downstream tool --
    nuclei included -- never ran. The gate has to ask the same question the runner
    will be asked, or it blocks authorized work and no longer predicts refusal.

    The port is stripped only for comparison; the value itself is still reported
    and still has to be covered by a rule for the same host.
    """
    text = (value or "").strip().lower()
    if "/" in text and "://" not in text:
        # A CIDR is a network, not a host with a path: "10.0.0.0/8" reduced to
        # "10.0.0.0" stops describing the range the rule authorized and starts
        # describing one address inside it.
        return text
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if text.startswith("["):  # bracketed IPv6 keeps its colons
        host, sep, _rest = text.partition("]")
        return host.lstrip("[").rstrip("]") if sep else text
    # A bare IPv6 literal is an address, not host:port -- splitting on the colon
    # would rewrite "fe80::1" into something the runner never compares against.
    if text.count(":") > 1:
        return text
    return text.rsplit(":", 1)[0] if ":" in text else text


def _wildcard_matches(domain: str, allowed: List[str]) -> bool:
    """Does any ROE pattern cover ``domain``?

    Takes the whole allowed list rather than one pattern, matching the
    orchestrator's ``_scope_matches_any(domain, allowed_list)`` predicate so a
    caller-supplied matcher and this default are interchangeable.
    """
    for pattern in allowed or []:
        base = (pattern or "").strip().lower()
        if not base:
            continue
        # The runner treats a CIDR pattern as a network and tests membership
        # (_match in app/roe/scope_check.py). Reconciliation has to ask the same
        # question: comparing "10.0.0.5" against "10.0.0.0/8" as strings refuses a
        # scope the runner will enforce, and the refusal looks like drift.
        if "/" in base and "://" not in base:
            try:
                return ipaddress.ip_address(domain) in ipaddress.ip_network(base)
            except ValueError:
                # Not an address, so it cannot be inside a network. A malformed
                # pattern is the rule author's problem, not a match.
                continue
        bare = base.lstrip("*").lstrip(".")
        if not bare:
            continue
        if domain == bare or domain.endswith("." + bare):
            return True
    return False


def reconcile(
    graph_scope: List[str],
    roe_scope: List[str],
    matcher: Optional[Callable[[str, str], bool]] = None,
) -> ScopeReconciliation:
    """Return the reconciliation of two scope records.

    ``matcher`` is the caller scope-comparison predicate. It receives the whole
    allowed list and has the signature ``(domain, allowed_list)``, the same
    shape as the orchestrator's own ``_scope_matches_any``. Defaults to exact
    or wildcard coverage, which is what an ROE rule expresses.
    """
    compare = matcher or _wildcard_matches
    result = ScopeReconciliation(
        graph_scope=list(graph_scope or []),
        roe_scope=list(roe_scope or []),
    )
    # Both sides are normalized here so a caller-supplied matcher receives the
    # same shape the orchestrator passes its own predicates, and a pattern typed
    # in a different case cannot silently fail to cover its host.
    allowed = [_scope_host(p) for p in result.roe_scope]
    allowed = [p for p in allowed if p]
    for raw in graph_scope or []:
        if not (raw or "").strip():
            continue
        if not compare(_scope_host(raw), allowed):
            result.unauthorized.append((raw or "").strip().lower())
    return result


async def fetch_roe_scope(
    base_url: str,
    investigation_id: str,
    token: str = "",
    timeout: float = 10.0,
    client: Optional[httpx.AsyncClient] = None,
) -> List[str]:
    """Read the enforced scope for an investigation from the active runner."""
    rules = await fetch_roe_rules(
        base_url, investigation_id, token=token, timeout=timeout, client=client
    )
    return extract_roe_patterns(rules)


async def fetch_roe_rules(
    base_url: str,
    investigation_id: str,
    token: str = "",
    timeout: float = 10.0,
    client: Optional[httpx.AsyncClient] = None,
) -> List[Dict[str, Any]]:
    """Read the enforced scope rules for an investigation from the active runner.

    Returns the normalized rule objects (pattern, rule_type, allow_aggressive)
    so recon can apply the ROE *policy* per host, not just its host ranges.
    """
    if not base_url:
        return []
    url = f"{base_url.rstrip('/')}/roe/scope/{investigation_id}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    owns_client = client is None
    http = client or httpx.AsyncClient(timeout=timeout)
    try:
        response = await http.get(url, headers=headers)
        response.raise_for_status()
        return extract_roe_rules(response.json())
    finally:
        if owns_client:
            await http.aclose()