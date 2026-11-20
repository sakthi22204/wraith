"""Severity adjudicated from evidence, not from how confident an author sounds.

A finding's severity used to be whatever string the caller supplied -- usually
the language model's, defaulting to "medium". That made the risk score a measure
of the model's mood: a UNION SELECT proven against an unauthenticated endpoint
could be filed as "medium" and contribute less to the score than a missing
header. It also ran the wrong way: nothing stopped a caller from writing
"critical" onto a finding that had never been executed, and the assessment
service sums severities regardless of status.

So severity is decided here, from what was actually observed, at the same write
paths that enforce ``require_validation_evidence``. Three rules:

  floor   -- the minimum the evidence supports. Derived from the vulnerability
             family, how deep the validation got (``validation_stage``), and
             whether the proof was obtained as an anonymous user. This is a hard
             minimum: an author cannot talk a proven unauthenticated injection
             down to "low", for the same reason a model cannot validate a
             finding by being confident about it.
  ceiling -- the maximum allowed. Nothing unexecuted is ever worse than
             "medium", and neither is a finding whose highest recorded stage is
             mere reachability or condition confirmation. High and critical need
             an observed consequence, not just an executed request.
  final   -- ``max(floor, min(claimed, ceiling))``. The author keeps the right
             to raise a finding above the floor when they know context the
             evidence does not (an admin-only route, a compensating control),
             but never past proven impact.

A claim backed only by the model's own probe stays unconfirmed here even if a
caller writes a validated status onto it. An advisory skill may propose a test;
only a deterministic harness or runtime observation can supply the impact rung
that opens the top half of the scale.

Every input is read from the merged node, so this is deterministic and
re-runnable: the same node always yields the same severity.
"""

from typing import Optional

#: Ordering used for comparisons. Severity is stored as a string because that is
#: what the rest of the pipeline reads, so the order lives here once.
_ORDER = ["info", "low", "medium", "high", "critical"]


def _norm(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def _rank(severity: Optional[str]) -> int:
    """Position of ``severity`` in the scale; unknown strings sort as info."""
    sev = _norm(severity)
    return _ORDER.index(sev) if sev in _ORDER else 0


#: Impact tier per vulnerability family: what the class of bug costs an attacker
#: once it is proven, independent of how it was found. Families absent from
#: this table are T1 -- they may still be proven, they simply carry no inherent
#: weight until someone shows impact.
_TIERS = {
    # T4 -- code or database execution.
    "SQL Injection": 4,
    "SQL Injection (time-based)": 4,
    # A boolean-blind oracle proves the input reached the query and was
    # evaluated, which is the same database access as an error- or time-based
    # confirmation. It is not a weaker class because it was quieter to observe.
    "SQL Injection (boolean-blind)": 4,
    "Injection Canary": 4,
    "Unrestricted File Upload": 4,
    # An injected shell command runs with the web server's privileges. It is
    # code execution in the same sense as SQL injection, so it belongs at the
    # top tier rather than inheriting the unmapped-family default.
    "Command Injection": 4,
    # T3 -- authorization failures and disclosure of other people's data.
    "Broken Access Control": 3,
    "Improper Access Control": 3,
    # A proven bypass of the login check is a full account takeover, not a
    # weaker cousin of one: the tautology either authenticated as someone or it
    # did not. Kept at T3 rather than T4 because no code was executed; the
    # anonymous bonus is what lifts it to critical, which is the correct grade
    # for reaching an account without credentials.
    "Authentication Bypass": 3,
    "Account Enumeration": 3,
    "Information Exposure": 3,
    "Weak JWT Handling": 3,
    # Signature-stripping is the same authentication failure as weak handling:
    # an unsigned token means anyone can claim any identity.
    "JWT Algorithm Confusion": 3,
    "Business Logic Flaw": 3,
    "Race Condition / TOCTOU": 3,
    "WebSocket Authentication Bypass": 3,
    "Mass Assignment": 3,
    # Arbitrary file read is disclosure of server-side data, not merely a
    # configuration weakness.
    "Path Traversal": 3,
    # T2 -- configuration and browser-facing weaknesses.
    #
    # Missing Rate Limiting sits here, not at T3, because its proof is a
    # *negative observation*: a limiter did not trigger. That is a real weakness
    # but not a demonstrated consequence, so even the anonymous bonus lifts it
    # only to "high" -- never "critical". A positive behavioural observation
    # (an injected query returning data) keeps its T3/T4 weight; the distinction
    # is the family, not a blanket cap on the rung.
    "Missing Rate Limiting": 2,
    "Missing Security Headers": 2,
    "CORS Misconfiguration": 2,
    "Host Header Injection": 2,
    "Open Redirect": 2,
    "Cross-Site Request Forgery": 2,
    "HTTP Request Smuggling": 2,
    "Cross-Site Scripting": 2,
    "HTML Injection": 2,
    "GraphQL Introspection": 2,
    "GraphQL Alias Over-fetch": 2,
}

#: Rungs that mean the bug itself was observed, not merely reachable. Lowercase
#: because they are compared against _norm()ed values, and "CONDITION_CONFIRMED"
#: != "condition_confirmed" is exactly the kind of silent miss that made every
#: finding look merely reachable.
_CONDITION = "condition_confirmed"
#: Rungs that mean the consequence was observed too.
_IMPACT = ("impact_confirmed", "exploitability_confirmed")

#: Severity an executed validation can never be scored below.
_UNVALIDATED_CEILING = "medium"

#: The anonymous probe marker written to ``probe_principal``.
ANONYMOUS = "unauthenticated"

_MODEL_SOURCES = {"agent_probe", "llm", "llm_only", "model", "ai"}
_HARNESS_SOURCES = {
    "exploitation",
    "mcp_tool_result",
    "mcp_tool_result_named",
    "harness",
    "deterministic_harness",
    "runner",
    "runtime",
}


def _sources(node: dict) -> Optional[frozenset]:
    raw = node.get("evidence_sources")
    if raw is None:
        return None
    values = [raw] if isinstance(raw, str) else list(raw)
    return frozenset(_norm(str(value)) for value in values if value)


def _is_llm_only(node: dict) -> bool:
    sources = _sources(node)
    if sources is None:
        return False
    return not sources or all(source in _MODEL_SOURCES for source in sources)


def _impact_observed(node: dict) -> bool:
    if _norm(node.get("validation_stage")) not in _IMPACT:
        return False
    if _is_llm_only(node):
        return False
    sources = _sources(node)
    if sources and not (sources & _HARNESS_SOURCES):
        return False
    return True


def _validated_statuses() -> frozenset:
    # Imported lazily: schema.py imports this module for the write paths, so a
    # module-level import here would close the cycle. Normalised to lowercase
    # because statuses arrive from enum members, from JSON, and from callers
    # that write them by hand in either case.
    from .schema import VALIDATED_STATUSES

    return frozenset(_norm(getattr(s, "value", s)) for s in VALIDATED_STATUSES)


def _is_validated(node: dict) -> bool:
    return _norm(node.get("status")) in _validated_statuses() and not _is_llm_only(node)


def severity_floor(node: dict) -> str:
    """Lowest severity the recorded evidence justifies.

    Returns "info" for a finding nothing has been proven about, which makes the
    floor inert rather than punitive on an unvalidated guess.
    """
    if not _is_validated(node):
        return "info"

    tier = _TIERS.get(node.get("vuln_type") or "", 1)
    stage = _norm(node.get("validation_stage"))
    anonymous = _norm(node.get("probe_principal")) == ANONYMOUS

    if stage not in _IMPACT and stage != _CONDITION:
        # Reachability was shown, the behaviour was not. That is a lead, not a
        # vulnerability: it earns the lowest tier and nothing more, and the
        # anonymous bonus does not apply either -- "anyone can reach it" is not
        # "anyone can exploit it".
        return "low"

    if not _impact_observed(node):
        return "medium" if tier >= 2 else "low"

    if anonymous:
        tier += 1
    elif tier == 4:
        # Proven code or database execution that required a session to reach is
        # still serious, but it is not the same as being available to anyone who
        # can send an HTTP request. This is the privilege-scope distinction a
        # CVSS vector encodes as PR:L versus PR:N, and it is why the anonymous
        # bonus is a gate at the top of the scale rather than only an addition.
        tier = 3

    return _ORDER[min(4, max(0, tier))]


def severity_ceiling(node: dict) -> str:
    """Highest severity this finding is allowed to carry."""
    if not _is_validated(node) or not _impact_observed(node):
        return _UNVALIDATED_CEILING
    return "critical"


def adjudicate_severity(node: dict) -> str:
    """Settle the severity this node may carry.

    ``node`` is the merged finding (existing properties plus the patch). The
    claimed value is read back from that same dict, so a caller cannot lower the
    floor by omitting severity, and cannot raise past the ceiling by asserting a
    number.
    """
    floor = severity_floor(node)
    ceiling = severity_ceiling(node)
    claimed = _norm(node.get("severity")) or floor

    return _ORDER[min(_rank(ceiling), max(_rank(floor), _rank(claimed)))]


def explain(node: dict) -> dict:
    """Human-readable account of a decision, for logs and report footers."""
    claimed = _norm(node.get("severity"))
    final = adjudicate_severity(node)
    return {
        "claimed": claimed or None,
        "final": final,
        "floor": severity_floor(node),
        "ceiling": severity_ceiling(node),
        "impact_observed": _impact_observed(node),
        "reason": (
            f"{final} (claimed {claimed or 'none'}; evidence supports "
            f"{severity_floor(node)}-{severity_ceiling(node)} for "
            f"{node.get('vuln_type')} at {node.get('validation_stage')}"
        ),
    }