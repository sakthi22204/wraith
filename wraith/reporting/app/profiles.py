"""Report profiles: the reader changes, the evidence bar does not.

A red-team deliverable and a bug-bounty submission are different documents for
different readers. The profile selects structure and guidance; it never changes
which findings are eligible. Confirmation is still decided by the graph and the
executed exchange, and a profile cannot promote an unvalidated hypothesis.

``auto`` derives the profile from the investigation's engagement_mode, so the
mode selected at investigation creation follows the report out without a second
switch for the operator to forget.
"""
from typing import Any, Dict, Iterable, Optional

AUTO = "auto"
FINAL = "final"
PROFILES = ("bugcrowd", "hackerone", "redteam", FINAL)

# The fields a submission needs before a triager can reproduce it. Missing any
# of these is an evidence gap, not a formatting preference: the report is not
# submittable until someone can replay it.
EVIDENCE_FIELDS = (
    ("poc_request", "no captured request"),
    ("poc_response", "no captured response"),
    ("expected_result", "no expected result"),
    ("actual_result", "no actual result"),
)


def resolve_profile(
    requested: Optional[str] = None,
    engagement_mode: Optional[str] = None,
) -> str:
    """Resolve an explicit profile or derive one from the engagement mode.

    ``redteam`` and ``both`` produce the client deliverable; ``wapt`` produces a
    bug-bounty-shaped writeup. An unknown explicit profile is an error rather
    than a silent fallback, because a report written for the wrong reader is
    worse than a failed request.
    """
    choice = (requested or AUTO).strip().lower()
    if choice != AUTO:
        if choice not in PROFILES:
            raise ValueError(
                f"unknown report profile {choice!r}; known: {', '.join((AUTO,) + PROFILES)}"
            )
        return choice
    mode = (engagement_mode or "wapt").strip().lower()
    return "redteam" if mode in ("redteam", "both") else "hackerone"


_GUIDANCE: Dict[str, Dict[str, Any]] = {
    "bugcrowd": {
        "reader": "Bugcrowd triager",
        "severity_system": "Bugcrowd VRT, with a manual severity request when the default underrates impact",
        "title": "<Vulnerability class> on <asset> leads to <impact>",
        "required_sections": [
            "Summary",
            "Affected asset and scope justification",
            "Steps to reproduce",
            "Expected vs actual result",
            "Impact",
            "Remediation",
            "Supporting evidence",
        ],
        "notes": [
            "Name the VRT category, or state why no exact category fits and which one you used.",
            "Put the severity request in the first body section, before the technical detail.",
            "Replay the request from a clean session; do not rely on a previous session's state.",
            "Do not submit rate-limiting findings on authentication flows unless the absence enables a concrete takeover or brute-force path.",
        ],
    },
    "hackerone": {
        "reader": "HackerOne triager",
        "severity_system": "CVSS 3.1, justified metric by metric",
        "title": "<Vulnerability class> in <component> allows <attacker> to <impact>",
        "required_sections": [
            "Summary",
            "Steps to reproduce",
            "Impact",
            "Supporting material",
            "Remediation",
        ],
        "notes": [
            "Every CVSS metric needs a one-line justification tied to observed behaviour.",
            "A missing security header or an enabled introspection endpoint is information, not a confirmed vulnerability, unless chained to a demonstrated impact.",
            "Redact cookies, tokens and third-party PII from screenshots and HAR files.",
            "State the exact asset and whether it is in scope; a finding on an out-of-scope host is not submittable because the test worked.",
        ],
    },
    "final": {
        "reader": "remediation owner and program triager",
        "severity_system": "CVSS 3.1 plus the report severity",
        "title": "<Vulnerability class> on <asset>",
        "required_sections": [
            "Summary",
            "Confirmed findings",
            "Affected endpoints",
            "Steps to reproduce",
            "Expected vs actual",
            "Impact",
            "Severity and CVSS",
            "Proof of exploitation (attached screenshots)",
            "Remediation",
        ],
        "notes": [
            "One combined report for the investigation; never split confirmed findings into separate downloads.",
            "Only confirmed findings appear in the findings section. Unvalidated hypotheses and rejected probes are listed separately and never counted as vulnerabilities.",
            "Attach the screenshot that shows the observed result for every finding; redact cookies, tokens and third-party PII before attaching.",
            "Replay the exact captured request from a clean session and state the observed status code and response delta.",
        ],
    },
    "redteam": {
        "reader": "Client security owner",
        "severity_system": "Engagement risk rating, with CVSS as supporting detail",
        "title": "<Finding> on <asset>",
        "required_sections": [
            "Subject",
            "Observations",
            "Description",
            "Impact",
            "Recommendation",
            "Proof of concept",
        ],
        "notes": [
            "Write for a remediation owner, not a bug-bounty triager: lead with what is exposed and what it lets an attacker do.",
            "Keep exploitation evidence, but describe business impact in the client's terms.",
            "Call out detection and response observations separately from vulnerabilities.",
            "Do not include unvalidated hypotheses in the findings section; list them as coverage gaps or leads.",
        ],
    },
}


def guidance_for(profile: str) -> Dict[str, Any]:
    try:
        return dict(_GUIDANCE[profile])
    except KeyError:
        raise ValueError(f"unknown report profile {profile!r}")


def evidence_gaps(finding: Any) -> list[str]:
    """Fields missing from a finding that a submittable report needs.

    Accepts either a ReportFinding or a mapping so the check can run before the
    model is constructed.
    """
    get = finding.get if isinstance(finding, dict) else lambda key, default=None: getattr(finding, key, default)
    gaps = []
    for field, message in EVIDENCE_FIELDS:
        if not get(field):
            gaps.append(message)
    return gaps


def is_submittable(finding: Any) -> bool:
    """A confirmed finding with every evidence field present.

    ``validation_state`` is the gate; the evidence check is what turns "the graph
    says confirmed" into "a triager can replay it".
    """
    get = finding.get if isinstance(finding, dict) else lambda key, default=None: getattr(finding, key, default)
    return get("validation_state") == "CONFIRMED" and not evidence_gaps(finding)


def evidence_warnings(findings: Iterable[Any]) -> list[dict]:
    warnings = []
    for finding in findings:
        if (finding.get("validation_state") if isinstance(finding, dict)
                else getattr(finding, "validation_state", None)) != "CONFIRMED":
            continue
        gaps = evidence_gaps(finding)
        if not gaps:
            continue
        title = finding.get("title") if isinstance(finding, dict) else getattr(finding, "title", "unknown")
        finding_id = finding.get("id") if isinstance(finding, dict) else getattr(finding, "id", None)
        warnings.append({
            "finding": title,
            "finding_id": finding_id,
            "gaps": gaps,
            "message": "confirmed but not submittable until the evidence is attached",
        })
    return warnings
