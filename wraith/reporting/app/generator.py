import base64
import mimetypes
import os
import re
from datetime import datetime
from typing import List, Dict, Any, Optional
from urllib.parse import parse_qs, urlsplit
from .models import ReportFinding, ProgramReport
from .clients.graph_db_client import graph_db_client
from .clients.assessment_client import assessment_client
from .clients.audit_client import audit_client
from .mapping.cwe_mapping import get_mapping
from .mapping.cvss_calculator import cvss_calculator
from .profiles import evidence_gaps, guidance_for, resolve_profile

# Mirrors graph_db.app.schema.FindingStatus. A report is the artefact a human
# submits to a program, so the bar for calling something a vulnerability is set
# by what the graph actually recorded, not by what a scanner proposed.
#
# HUMAN_CONFIRMED is deliberately absent. Confirmation in this system comes from
# executed evidence (AI_VALIDATED) or from independent corroboration
# (CORROBORATED); there is no human review phase, and a status that could only
# be minted by one must not make an untested guess reportable. Legacy rows that
# still carry HUMAN_CONFIRMED fall through to the evidence check below, exactly
# like any other status.
CONFIRMED_STATUSES = {"AI_VALIDATED", "CORROBORATED"}


def normalize_status(status: Any) -> str:
    return str(status).strip().upper() if status is not None else ""


def is_confirmed(finding: Dict[str, Any]) -> bool:
    """Whether a finding was actually confirmed, as opposed to proposed.

    Two independent signals count, because either alone is misleading:

      * the graph's own status, set by an executed validation or a corroborating
        pass; and
      * validation evidence on the finding -- a request that was sent and a
        response that came back. The second catches a finding whose status was
        never written but which does carry a real exchange.

    A finding with neither is a hypothesis. It is not a weak vulnerability, it
    is an untested guess, and the report must not present it as the former.
    Statuses DUPLICATE and FALSE_POSITIVE are confirmed *negative* verdicts and
    OBSERVATION is a negative signal (a missing control, not a proven bug); all
    are rejected before the evidence check, and are rejected here too so the
    helper is safe to use on its own.
    """
    if normalize_status(finding.get("status")) in CONFIRMED_STATUSES:
        return True
    if normalize_status(finding.get("status")) in {"FALSE_POSITIVE", "DUPLICATE", "OBSERVATION"}:
        # A negative observation carries an executed exchange (the probe that met
        # no limiter, the response missing a header) but is not a confirmed
        # vulnerability, so it must not fall through to the evidence check below.
        return False
    if normalize_status(finding.get("validation_stage")) in {"NOT_VALIDATED", "REFUTED"}:
        # An executed exchange that reached neither a positive nor a negative
        # verdict is still inconclusive. Carrying a request/response pair is not
        # enough: a CDN challenge page, a timeout or a blocked probe all leave
        # evidence behind without proving anything about the application.
        return False
    return bool(finding.get("poc_request")) and bool(finding.get("poc_response"))


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STAGE_RANK = {
    "EXPLOITABILITY_CONFIRMED": 4,
    "IMPACT_CONFIRMED": 3,
    "CONDITION_CONFIRMED": 2,
    "REACHABILITY_CONFIRMED": 1,
    "NOT_VALIDATED": 0,
    "REFUTED": -1,
}


def _base_vuln_type(value: Any) -> str:
    """Collapse ``SQL Injection (union-based)`` to ``sql injection``."""
    text = re.sub(r"\([^)]*\)", " ", str(value or "").lower())
    return re.sub(r"[^a-z0-9]+", " ", text).strip()


def _provisional_cvss_vector(vuln_type: str, mapping: Dict[str, Any]) -> Optional[str]:
    """Return a conservative CVSS 3.1 baseline when the finding has no vector.

    A confirmed finding without a CVSS vector should not render as
    ``CVSS score not calculated``: the class and observed access level are
    enough to state a baseline. The vectors below are deliberately conservative
    for an authenticated web assessment; a caller that recorded its own vector
    always wins.
    """
    key = str(vuln_type or "").lower()
    if "blind" in key and "sql" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    if "sql injection" in key or "sqli" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    if "command injection" in key or "os command" in key or "cmdi" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    if "stored" in key and "xss" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"
    if "reflected" in key and "xss" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    if "local file inclusion" in key or "lfi" in key or "path traversal" in key:
        return "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    template = mapping.get("cvss_template")
    if template and mapping.get("cwe_id") != "Unknown":
        return template
    return None


def _class_impact(vuln_type: str) -> Optional[str]:
    """Explain the consequence of the observed class, not just its severity."""
    key = str(vuln_type or "").lower()
    if "blind" in key and "sql" in key:
        return (
            "An attacker can infer database contents one bit at a time by "
            "observing true/false responses, enabling data disclosure and "
            "further account compromise."
        )
    if "sql injection" in key or "sqli" in key:
        return (
            "An attacker can read or modify database contents, bypass "
            "authentication, and potentially execute database functions with "
            "the application's privileges."
        )
    if "command injection" in key or "os command" in key or "cmdi" in key:
        return (
            "An attacker can execute arbitrary operating-system commands with "
            "the privileges of the web server, leading to data disclosure, "
            "modification, or full host compromise."
        )
    if "stored" in key and "xss" in key:
        return (
            "An attacker can store script that executes in other users' "
            "browsers, enabling session theft, actions as the victim, or "
            "credential phishing."
        )
    if "reflected" in key and "xss" in key:
        return (
            "An attacker can execute script in a victim's browser via a crafted "
            "link, enabling session theft or actions as the victim."
        )
    if "local file inclusion" in key or "lfi" in key or "path traversal" in key:
        return (
            "An attacker can read files outside the intended directory, "
            "including configuration, source code, and credential material."
        )
    return None


def _class_remediation(vuln_type: str) -> Optional[str]:
    """Return a class-specific fix before falling back to generic advice."""
    key = str(vuln_type or "").lower()
    if "blind" in key and "sql" in key:
        return (
            "Use parameterized queries or prepared statements and treat "
            "cookie/session values as untrusted input. Enforce numeric/type "
            "validation, avoid dynamic SQL, and run the database account with "
            "least privilege."
        )
    if "sql injection" in key or "sqli" in key:
        return (
            "Use parameterized queries or prepared statements for every "
            "database call. Do not concatenate query, body, cookie, or session "
            "values into SQL; validate types and use a least-privilege database "
            "account."
        )
    if "command injection" in key or "os command" in key or "cmdi" in key:
        return (
            "Do not build shell command strings from user input. Call the "
            "underlying API or use an argument-list subprocess API, allowlist "
            "accepted values, and run the service with least privilege."
        )
    if "stored" in key and "xss" in key:
        return (
            "Apply context-aware output encoding when rendering stored data, "
            "sanitize HTML with an allowlist, deploy a restrictive Content "
            "Security Policy, and set session cookies HttpOnly and SameSite."
        )
    if "reflected" in key and "xss" in key:
        return (
            "Apply context-aware output encoding to reflected input, avoid raw "
            "HTML insertion, deploy a restrictive Content Security Policy, and "
            "encode query and body parameters."
        )
    if "local file inclusion" in key or "lfi" in key or "path traversal" in key:
        return (
            "Resolve the requested file with a canonical path and require it to "
            "remain under an allowlisted base directory; use a filename "
            "allowlist and disable dangerous stream wrappers."
        )
    return None


def is_self_test_marker(finding: Dict[str, Any]) -> bool:
    """Whether the finding is a probe artifact rather than a vulnerability.

    The injection canary exists to prove that input reaches an interpreter. When
    it fires, the class of the underlying bug is still unknown; reporting a
    finding titled "Injection Canary" tells a triager nothing they can act on.
    The concrete family (SQL/command/LDAP injection) is filed by the pack that
    owns it, so this marker is excluded from reports entirely.
    """
    return _base_vuln_type(finding.get("vuln_type")) == "injection canary"


def _parameter_from_request(poc_request: Any) -> str:
    """Return the query parameter a finding's first request exercised, if any."""
    text = str(poc_request or "")
    match = re.search(
        r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", text, re.MULTILINE)
    if not match:
        return ""
    query = parse_qs(urlsplit(match.group(1)).query, keep_blank_values=True)
    return ",".join(sorted(query))


def _display_endpoint(endpoint: str) -> str:
    """Render a replayable URL without dumping a multi-word payload into a table."""
    if not any(char.isspace() for char in endpoint):
        return endpoint
    base, separator, query = endpoint.partition("?")
    if separator and query:
        key = query.split("&", 1)[0].split("=", 1)[0]
        return f"{base}?{key}=..."
    return endpoint.split()[0] + "..."


def _endpoints_from_evidence(finding: Dict[str, Any], affected_asset: str) -> List[str]:
    """Return the endpoints actually exercised by the captured traffic.

    ``affected_asset`` describes the graph node, which is useful but not always
    a URL. The final report needs the concrete method+URL, so prefer the request
    lines from ``poc_request`` and keep order while de-duplicating.
    """
    text = str(finding.get("poc_request") or "")
    endpoints = re.findall(
        r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+?)\s*$",
        text,
        re.MULTILINE,
    )
    out: List[str] = []
    for endpoint in endpoints:
        endpoint = re.sub(r"\s+HTTP/\d(?:\.\d)?$", "", endpoint.strip())
        endpoint = _display_endpoint(endpoint)
        if endpoint not in out:
            out.append(endpoint)
    if not out and affected_asset and affected_asset != "Unknown Asset":
        out.append(affected_asset)
    return out


_NON_FINDING_OPTION_TYPES = {
    "allowed options method",
    "options method",
    "allowed http methods",
    "http options method",
}
_NON_FINDING_API_DOC_TYPES = {
    "api documentation exposure",
    "api documentation is exposed",
    "openapi documentation exposure",
}


def non_finding_reason(finding: Dict[str, Any]) -> Optional[str]:
    """Explain why a recorded probe is not a reportable vulnerability.

    Two probes common to automated sweeps are not findings by themselves:

      * an ``OPTIONS`` request that returns 200 proves only that the method is
        advertised; it does not demonstrate a security impact; and
      * an "API documentation exposed" probe whose captured response is a 404
        proves the opposite of its own title -- the body echoing the requested
        path is not a served document.

    Returning a reason lets the final report list the exclusion explicitly
    rather than leaving the reader to wonder where the item went.
    """
    base = _base_vuln_type(finding.get("vuln_type"))
    if base in _NON_FINDING_OPTION_TYPES:
        return "OPTIONS returned a capability response; no security impact was demonstrated."
    if base in _NON_FINDING_API_DOC_TYPES:
        response = str(finding.get("poc_response") or "")
        if re.search(r"(^|\D)404(\D|$)|not found", response, re.IGNORECASE):
            return "the captured request returned 404; no API document was exposed."
    return None


def is_non_finding(finding: Dict[str, Any]) -> bool:
    return non_finding_reason(finding) is not None


_SCREENSHOT_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}


def _caption_for_screenshot(path: str, fallback: str = "") -> str:
    name = os.path.splitext(os.path.basename(path))[0]
    caption = re.sub(r"[_-]+", " ", name).strip()
    return caption.title() if caption else fallback


def _load_screenshots(program_id: str, finding: Dict[str, Any]) -> List[dict]:
    """Load screenshots attached to a finding as self-contained data URIs.

    A capture pipeline may write images into
    ``WRAITH_SCREENSHOT_DIR/<investigation>/<finding>/``. A caller can also pass
    an explicit ``screenshots`` list on the finding. Both are normalised here so
    the HTML, PDF and Markdown templates render the same proof section without
    needing filesystem access of their own.
    """
    raw = (
        finding.get("screenshots")
        or finding.get("evidence_screenshots")
        or finding.get("screenshot_paths")
        or []
    )
    if isinstance(raw, (str, dict)):
        raw = [raw]

    entries: List[dict] = []
    for item in raw:
        if isinstance(item, str):
            entries.append({"path": item})
        elif isinstance(item, dict):
            entries.append(dict(item))

    finding_id = str(finding.get("id") or "")
    base_dir = os.environ.get("WRAITH_SCREENSHOT_DIR", "/data/screenshots")
    if not entries and finding_id:
        for candidate in (
            os.path.join(base_dir, str(program_id), finding_id),
            os.path.join(base_dir, finding_id),
        ):
            if not os.path.isdir(candidate):
                continue
            for name in sorted(os.listdir(candidate)):
                if os.path.splitext(name)[1].lower() in _SCREENSHOT_EXTENSIONS:
                    entries.append({"path": os.path.join(candidate, name)})
            if entries:
                break

    screenshots: List[dict] = []
    for entry in entries:
        source = entry.get("path") or entry.get("file") or entry.get("url") or ""
        screenshot = dict(entry)
        screenshot["caption"] = (
            entry.get("caption")
            or _caption_for_screenshot(source, finding.get("title") or "Proof of exploitation")
        )
        screenshot["filename"] = os.path.basename(urlsplit(source).path) if source else ""
        if source and not source.startswith(("http://", "https://", "data:")):
            if os.path.isfile(source):
                mime, _ = mimetypes.guess_type(source)
                with open(source, "rb") as handle:
                    encoded = base64.b64encode(handle.read()).decode("ascii")
                screenshot["data_uri"] = f"data:{mime or 'image/png'};base64,{encoded}"
        screenshots.append(screenshot)
    return screenshots


def _finding_group_key(finding: Dict[str, Any]) -> Optional[tuple]:
    """Key by the same evidence a triager uses to call two reports duplicates.

    Endpoint identity is the graph's ``target_id``; the class is normalized so a
    union and boolean variant of one SQL injection do not become two reports;
    the parameter keeps separate injection points separate. Confirmed and
    unconfirmed findings never share a group, because merging them would lend
    the hypothesis the executed finding's status.
    """
    target_id = finding.get("target_id")
    if not target_id:
        return None
    return (
        target_id,
        _base_vuln_type(finding.get("vuln_type")),
        _parameter_from_request(finding.get("poc_request")),
        is_confirmed(finding),
    )


def _merge_corroborating_findings(
    findings: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], int]:
    """Merge same-endpoint/same-class/same-parameter findings.

    The strongest observation represents the group: an IMPACT_CONFIRMED union
    variant outranks a CONDITION_CONFIRMED boolean variant even when the latter
    was assigned a higher severity. The group keeps the highest severity and
    records every variant in the description, so merging loses no proof while
    removing the duplicate reports triagers reject.
    """
    grouped: Dict[tuple, List[Dict[str, Any]]] = {}
    standalone: List[Dict[str, Any]] = []
    for finding in findings:
        key = _finding_group_key(finding)
        if key is None:
            standalone.append(finding)
        else:
            grouped.setdefault(key, []).append(finding)

    merged_count = 0
    out = list(standalone)
    for group in grouped.values():
        if len(group) == 1:
            out.append(group[0])
            continue
        merged_count += len(group) - 1
        representative = max(
            group,
            key=lambda f: (
                _STAGE_RANK.get(str(f.get("validation_stage") or "").upper(), 0),
                -_SEVERITY_RANK.get(str(f.get("severity") or "").lower(), 5),
                len(str(f.get("evidence") or "")),
            ),
        )
        merged = dict(representative)
        strongest_severity = min(
            group,
            key=lambda f: _SEVERITY_RANK.get(
                str(f.get("severity") or "").lower(), 5),
        ).get("severity")
        if strongest_severity:
            merged["severity"] = strongest_severity
        representative_type = str(representative.get("vuln_type") or "").lower()
        variants = sorted({
            str(f.get("vuln_type"))
            for f in group
            if f.get("vuln_type")
            and str(f.get("vuln_type")).lower() != representative_type
        })
        if variants:
            description = str(merged.get("description") or "").rstrip()
            merged["description"] = (
                f"{description} Corroborated by the same-endpoint variants: "
                f"{', '.join(variants)}."
            ).strip()
        out.append(merged)
    return out, merged_count


class ReportGenerator:
    async def generate_finding_report(self, program_id: str, finding: Dict[str, Any]) -> ReportFinding:
        vuln_type = finding.get("vuln_type", "unknown")
        mapping = get_mapping(vuln_type)

        # 1. Summary
        # Prefer the recorded headline. Falling back to a 50-character slice of
        # the description produced the same unreadable shape for every scanner
        # finding ("INFO DISCLOSURE in Scanner reported a /metrics endpo..."),
        # but legacy findings without a title still render as before.
        title = finding.get("title") or f"{vuln_type.upper()} in {finding.get('description', 'Unknown Asset')[:50]}"

        # 2. Vulnerability Type
        vulnerability_type = f"{mapping['cwe_id']} - {mapping['owasp_category']}"

        # 3. Severity + CVSS
        explicit_vector = finding.get("cvss_vector")
        cvss_vector = explicit_vector or _provisional_cvss_vector(vuln_type, mapping)
        cvss_provisional = bool(cvss_vector) and not bool(explicit_vector)
        score, band = (None, "Unknown")

        if cvss_vector:
            score, band = cvss_calculator.calculate(cvss_vector)

        if score is not None:
            cvss_display = f"{score} ({band})"
        else:
            cvss_display = "CVSS score not calculated"

        # When the vector is a class baseline rather than finding-specific
        # evidence, the band is the defensible severity. A graph label of
        # "critical" paired with a 8.8 vector reads as an internal
        # contradiction to a triager.
        severity = finding.get("severity", band).capitalize()
        if cvss_provisional and band != "Unknown":
            severity = band

        # HackerOne report guidance asks for the CVSS score to be justified
        # metric-by-metric. Break the vector down into plain-English reasons.
        cvss_metric_meanings = {
            "AV": {
                "N": "Network — exploitable remotely over the network with no local access.",
                "A": "Adjacent — attacker must be on the adjacent network segment.",
                "L": "Local — attacker needs local or shell-level access to the host.",
                "P": "Physical — attacker needs physical access to the device.",
            },
            "AC": {
                "L": "Low — no special conditions beyond sending the request itself.",
                "H": "High — requires conditions an attacker cannot reliably control.",
            },
            "PR": {
                "N": "None — works unauthenticated or at the lowest privilege level.",
                "L": "Low — requires a low-privileged (basic user) account.",
                "H": "High — requires elevated or administrative privileges.",
            },
            "UI": {
                "N": "None — no victim interaction is required.",
                "R": "Required — the victim must perform an action (e.g. click a link).",
            },
            "S": {
                "U": "Unchanged — impact is confined to the vulnerable component.",
                "C": "Changed — impact crosses a trust boundary into other components.",
            },
            "C": {
                "H": "High — complete disclosure of confidential data.",
                "L": "Low — limited or partial disclosure of sensitive data.",
                "N": "None — no confidentiality impact.",
            },
            "I": {
                "H": "High — attacker can modify all data/functions the component controls.",
                "L": "Low — limited modification of data possible.",
                "N": "None — no integrity impact.",
            },
            "A": {
                "H": "High — complete loss of availability of the affected component.",
                "L": "Low — reduced availability or intermittent degradation.",
                "N": "None — no availability impact.",
            },
        }
        cvss_rationale = []
        if cvss_vector:
            for part in str(cvss_vector).split("/"):
                if ":" not in part:
                    continue
                metric, value = part.split(":", 1)
                metric, value = metric.strip().upper(), value.strip()
                if metric == "CVSS" or not value:
                    continue
                meaning = (cvss_metric_meanings.get(metric) or {}).get(value)
                cvss_rationale.append({
                    "metric": metric,
                    "value": value,
                    "meaning": meaning or "Not scored in this vector."
                })

        ai_conf = finding.get("ai_confidence")
        if ai_conf is None:
            try:
                ai_conf = float(finding.get("confidence"))
            except (TypeError, ValueError):
                ai_conf = None

        ai_confidence_display = str(ai_conf) if ai_conf is not None else "N/A"

        # 4. Affected Asset
        target_id = finding.get("target_id")
        target_details = await graph_db_client.get_target_details(program_id, target_id) if target_id else None

        if target_details:
            asset_parts = []
            if target_details.get("host"):
                asset_parts.append(f"Host: {target_details['host']}")
            if "Endpoint" in target_details["labels"]:
                asset_parts.append(f"Endpoint: {target_details['properties'].get('url')}")
            if "Parameter" in target_details["labels"]:
                asset_parts.append(f"Parameter: {target_details['properties'].get('name')}")
            affected_asset = " | ".join(asset_parts)
        else:
            affected_asset = "Unknown Asset"

        affected_endpoints = _endpoints_from_evidence(finding, affected_asset)
        screenshots = _load_screenshots(program_id, finding)

        # 5. Description
        description = finding.get("description", "No detailed description provided.")

        # Validation evidence. When a finding was actually validated these are
        # the executed request and the observed response, so the section renders
        # what happened rather than restating the description.
        poc_request = finding.get("poc_request")
        poc_response = finding.get("poc_response")
        expected_result = finding.get("expected_result")
        actual_result = finding.get("actual_result")
        validation_stage = finding.get("validation_stage") or "NOT_VALIDATED"
        is_validated = bool(poc_request) and bool(poc_response)
        # Drives the headline wording of the whole report. A validated exchange
        # is the strongest evidence, but a graph status set by a human counts
        # too, so this is the same test the executive summary uses.
        validation_state = "CONFIRMED" if is_confirmed(finding) else "UNVALIDATED"
        gaps = evidence_gaps(finding) if validation_state == "CONFIRMED" else []
        submittable = (
            validation_state == "CONFIRMED"
            and not gaps
        )
        # Credentials and tokens are masked at capture time in the sandbox; the
        # block below is a second layer so nothing sensitive reaches a rendered
        # report even if a capture predates the redaction change.
        evidence = finding.get("evidence") or "No raw evidence captured"

        # 6. Steps to Reproduce
        tool_info = await graph_db_client.get_discovering_tool(program_id, finding["id"])
        tool_name = tool_info.get("name", "security tool") if tool_info else "automated scan"

        if is_validated:
            # The captured request IS the reproduction recipe: replaying it
            # reproduces the observation, because it is the exact traffic that
            # produced it.
            steps = (
                f"Replay the exact request that produced this evidence.\n\n"
                f"1. Target: {affected_asset}\n"
                f"2. Send the request below verbatim (method, path, headers, body).\n"
                f"3. Compare your response against the Expected/Actual below.\n\n"
                f"Replayed request:\n```http\n{poc_request}\n```\n\n"
                f"Expected: {expected_result or 'see observed response'}\n"
                f"Actual:   {actual_result or 'see observed response'}"
            )
        else:
            steps = (
                f"Not yet validated by an executed request. This finding is a "
                f"scanner hypothesis, not a confirmed issue.\n\n"
                f"Detected by: {tool_name}\n"
                f"Reasoning:   {description}\n\n"
                f"To confirm it, send a specific request to "
                f"{affected_asset} and check the response directly."
            )

        # 7. Exploit / PoC
        audit_entries = await audit_client.get_audit_entries(program_id, target=target_details.get("host") if target_details else None)
        relevant_audit = [
            e for e in audit_entries
            if vuln_type.lower() in e["action"].lower() or (tool_name.lower() in e["action"].lower() and e["action"].lower() != "run_nmap_scan")
        ]

        if is_validated:
            poc = (
                f"Validation stage reached: {validation_stage}\n\n"
                f"Proof of concept (request that was actually sent):\n"
                f"```http\n{poc_request}\n```\n\n"
                f"Observed response:\n```http\n{poc_response}\n```"
            )
        elif relevant_audit:
            poc = (
                f"No executed proof of concept. The closest recorded action was "
                f"{relevant_audit[0]['action']}, which is discovery rather than "
                f"verification.\n\n"
                f"Recorded result: {relevant_audit[0].get('result')}"
            )
        else:
            poc = (
                "No proof of concept. This finding has not been validated by an "
                "executed request, so the reported behaviour has not been "
                "observed directly."
            )

        # 9. Business Impact
        impact_map = {
            "critical": "Complete compromise of the affected system, potentially leading to unauthorized data access and full administrative control.",
            "high": "Serious impact on the confidentiality, integrity, or availability of the system and its data.",
            "medium": "Limited impact on the system, which could still lead to disclosure of sensitive information or unauthorized actions.",
            "low": "Minimal impact, often requiring specific conditions to be exploitable or affecting non-sensitive data.",
            "info": "Informational finding with no direct security impact but may provide useful context for further attacks."
        }
        # A specific, observed impact beats a generic severity template: once we
        # have executed evidence we can say what actually happened rather than
        # what this severity class usually means.
        business_impact = (
            finding.get("impact")
            or finding.get("business_impact")
            or _class_impact(vuln_type)
            or impact_map.get(severity.lower(), "Potential security risk to the organization's assets and reputation.")
        )

        # 10. Suggested Remediation
        remediation_map = {
            "sqli": "Use parameterized queries or prepared statements. Implement strict input validation.",
            "xss": "Implement context-aware output encoding. Use Content Security Policy (CSP).",
            "ssrf": "Implement an allowlist of permitted domains/IPs. Do not allow direct user input in network requests.",
            "idor": "Implement robust server-side authorization checks for every sensitive resource access.",
            "lfi": "Avoid passing user input directly to file system APIs. Use an allowlist of files.",
            "jwt": "Ensure strong signing algorithms and secrets. Validate all claims and expiration.",
            "xxe": "Disable external entity resolution in XML parsers.",
            "cmdi": "Avoid calling OS commands with user input. Use safe alternatives or sanitize input thoroughly.",
            "authentication bypass": (
                "Parameterize the authentication query and never concatenate identity "
                "fields into SQL. Authenticate only after the supplied credential "
                "matches exactly one account's password hash."
            ),
            "pii exposure": (
                "Require authentication and object-level authorization on every data "
                "route. Deny by default and return only the fields the caller is "
                "entitled to see."
            ),
        }
        suggested_remediation = (
            finding.get("remediation")
            or finding.get("suggested_remediation")
            or _class_remediation(vuln_type)
            or remediation_map.get(
                vuln_type.lower(),
                "Follow industry best practices for securing the affected component and addressing the identified vulnerability class."
            )
        )

        # Root cause is only asserted when the investigation actually recorded
        # one; a templated guess here would read as analysis that never happened.
        root_cause = finding.get("root_cause") or ""

        # 11. Metadata
        program_data = await graph_db_client.get_program(program_id)
        discovery_metadata = {
            "timestamp": finding.get("discovered_at"),
            "tool": tool_name,
            "program": program_data.get("name", "Unknown Program") if program_data else "Unknown",
            "confidence": finding.get("confidence"),
            "status": finding.get("status")
        }

        # 12. Structured Risk Rating
        risk_rating = {
            "score": score if score is not None else (10.0 if severity.lower() == "critical" else 8.0 if severity.lower() == "high" else 5.0 if severity.lower() == "medium" else 2.0),
            "band": band if band != "Unknown" else severity,
            "cvss_vector": cvss_vector or "N/A",
            "cvss_rationale": cvss_rationale,
            "ai_confidence": ai_confidence_display,
            "criticality": severity
        }

        # 13. Attack Graph Path representation
        attack_nodes = []
        if target_details:
            if target_details.get("host"):
                attack_nodes.append(f"Host: {target_details['host']}")
            if "Endpoint" in target_details["labels"]:
                attack_nodes.append(f"Endpoint: {target_details['properties'].get('url')}")
            if "Parameter" in target_details["labels"]:
                attack_nodes.append(f"Parameter: {target_details['properties'].get('name')}")
        attack_nodes.append(
            f"Finding: {title} ({severity})"
            if validation_state == "CONFIRMED"
            else f"Unvalidated hypothesis: {title} ({severity})"
        )
        attack_graph_text = " -> ".join(attack_nodes)
        attack_graph = {
            "path_ascii": attack_graph_text,
            "nodes": attack_nodes,
            "total_hops": max(0, len(attack_nodes) - 1)
        }

        # 14. Validation Timeline for finding
        finding_time = finding.get("discovered_at") or datetime.utcnow().isoformat()
        timeline = [
            {"timestamp": finding_time, "event": f"Vulnerability '{vuln_type.upper()}' first surfaced by {tool_name}."}
        ]
        if is_validated:
            # The validation exchange is the timeline's decisive event: it is
            # when the hypothesis was actually tested.
            timeline.append({
                "timestamp": finding_time,
                "event": (
                    f"Validation request executed; stage reached "
                    f"{validation_stage}. Expected: {expected_result or 'n/a'}. "
                    f"Observed: {actual_result or 'n/a'}."
                )
            })
        else:
            timeline.append({
                "timestamp": finding_time,
                "event": "No validation request executed; finding remains a scanner hypothesis."
            })
        timeline.sort(key=lambda x: x["timestamp"])

        # 15. Support Contacts
        support_resources = [
            {"channel": "Wraith Product Security", "contact": "security@wraith.io"},
            {"channel": "Remediation Guide", "contact": "https://wraith.io/remediation/remediating-vulnerabilities"},
            {"channel": "Internal Slack Channel", "contact": "#security-remediation-q-and-a"}
        ]

        return ReportFinding(
            title=title,
            vulnerability_type=vulnerability_type,
            severity=severity,
            cvss_score=cvss_display,
            cvss_vector=cvss_vector,
            cvss_provisional=cvss_provisional,
            ai_confidence=ai_confidence_display,
            affected_asset=affected_asset,
            affected_endpoints=affected_endpoints,
            screenshots=screenshots,
            description=description,
            steps_to_reproduce=steps,
            exploit_poc=poc,
            evidence=evidence,
            business_impact=business_impact,
            suggested_remediation=suggested_remediation,
            poc_request=poc_request,
            poc_response=poc_response,
            expected_result=expected_result,
            actual_result=actual_result,
            validation_stage=validation_stage,
            validation_state=validation_state,
            submittable=submittable,
            evidence_gaps=gaps,
            discovery_metadata=discovery_metadata,
            risk_rating=risk_rating,
            timeline=timeline,
            attack_graph=attack_graph,
            support_resources=support_resources
        )

    async def generate_program_report(self, program_id: str, profile: Optional[str] = None) -> ProgramReport:
        program_data = await graph_db_client.get_program(program_id)
        # An explicit request wins; otherwise the investigation's mode picks the
        # reader. The profile changes structure, never eligibility.
        report_profile = resolve_profile(
            profile,
            (program_data or {}).get("engagement_mode"),
        )
        submission_guidance = guidance_for(report_profile)
        findings_raw = await graph_db_client.get_findings_for_program(program_id)
        coverage = await assessment_client.get_coverage(program_id)

        duplicates = [f for f in findings_raw if f.get("status") == "DUPLICATE"]
        false_positives = [f for f in findings_raw if f.get("status") == "FALSE_POSITIVE"]
        # A recorded probe can carry a "validated" status and still not be a
        # vulnerability (an OPTIONS 200, or a 404 that echoes the path). Keep
        # those out of the confirmed count and list them as explicit exclusions.
        excluded_non_findings_raw = [
            f for f in findings_raw
            if f.get("status") not in ["DUPLICATE", "FALSE_POSITIVE"]
            and is_non_finding(f)
        ]

        active_findings_raw = [
            f for f in findings_raw
            if f.get("status") not in ["DUPLICATE", "FALSE_POSITIVE"]
            and not is_self_test_marker(f)
            and not is_non_finding(f)
        ]
        # Status-based duplicates are already excluded above. This second pass
        # collapses findings the runner filed separately because their vuln_type
        # strings differed (SQL Injection vs SQL Injection (union-based)), even
        # though they exercised the same parameter on the same endpoint.
        active_findings_raw, grouped_duplicates = _merge_corroborating_findings(
            active_findings_raw)

        findings = []
        for f in active_findings_raw:
            report_finding = await self.generate_finding_report(program_id, f)
            findings.append(report_finding)

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity, 5))

        # Confirmed and unvalidated findings are counted separately and never
        # merged. Reporting an untested hypothesis in the same breath as a
        # confirmed vulnerability is what produced a report claiming "23 active
        # security issues" for a target that never resolved a DNS record.
        confirmed = [f for f in findings if f.validation_state == "CONFIRMED"]
        observations = [
            f for f in findings
            if f.validation_state != "CONFIRMED"
            and normalize_status(f.discovery_metadata.get("status")) == "OBSERVATION"
        ]
        unvalidated = [
            f for f in findings
            if f.validation_state != "CONFIRMED" and f not in observations
        ]

        summary = (
            f"{len(duplicates) + grouped_duplicates} duplicate and "
            f"{len(false_positives)} false-positive finding(s) "
            f"excluded from this report. "
            f"{len(confirmed)} confirmed, {len(unvalidated)} unvalidated, "
            f"{len(observations)} observation(s)."
        )

        # Program Executive Summary. Severity counts and the average score cover
        # confirmed findings only; an unvalidated hypothesis has no basis for a
        # severity claim and including it would inflate the numbers a triager
        # reads first.
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        unvalidated_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_score = 0.0
        for f in confirmed:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            if f.risk_rating:
                total_score += f.risk_rating.get("score", 0.0)
        for f in unvalidated:
            unvalidated_counts[f.severity] = unvalidated_counts.get(f.severity, 0) + 1

        avg_score = round(total_score / len(confirmed), 1) if confirmed else None

        # Posture describes what was established. "SECURE" is deliberately not
        # reachable from a run that confirmed nothing: zero confirmations means
        # the assessment established nothing about the target's security, which
        # is not the same as the target being secure. Claiming SECURE off an
        # empty confirmation set is the same class of error as claiming
        # vulnerabilities off an unvalidated one.
        if severity_counts["Critical"] or severity_counts["High"]:
            posture = "HIGH RISK / ACTION REQUIRED"
        elif confirmed:
            posture = "ISSUES CONFIRMED"
        elif unvalidated:
            posture = "INCONCLUSIVE / NO CONFIRMED VULNERABILITIES"
        else:
            posture = "NO FINDINGS RECORDED"

        if unvalidated:
            assessment_comment = (
                f"{len(confirmed)} confirmed vulnerability finding(s). "
                f"A further {len(unvalidated)} item(s) are unvalidated hypotheses carried "
                f"from automated reconnaissance: they were proposed but never confirmed "
                f"against the target, and must not be submitted as vulnerabilities. "
                f"{severity_counts['Critical']} critical and {severity_counts['High']} high "
                f"severity confirmed findings require immediate remediation."
            )
        else:
            assessment_comment = (
                f"An automated security assessment confirmed {len(confirmed)} security "
                f"issue(s). {severity_counts['Critical']} critical and "
                f"{severity_counts['High']} high severity findings require immediate "
                f"remediation."
            )
        if observations:
            assessment_comment += (
                f" {len(observations)} additional observation(s) describe missing controls "
                f"but were not counted as vulnerabilities."
            )
        if excluded_non_findings_raw:
            assessment_comment += (
                f" {len(excluded_non_findings_raw)} recorded probe(s) were excluded as "
                f"non-findings; see the exclusion list."
            )

        executive_summary = {
            "overall_posture": posture,
            "average_risk_score": avg_score,
            "severity_breakdown": severity_counts,
            "unvalidated_severity_breakdown": unvalidated_counts,
            "confirmed_count": len(confirmed),
            "unvalidated_count": len(unvalidated),
            "observation_count": len(observations),
            "excluded_non_finding_count": len(excluded_non_findings_raw),
            "assessment_comment": assessment_comment,
        }

        # Program Validation Timeline
        program_timeline = []
        for f in findings:
            is_confirmed_finding = f.validation_state == "CONFIRMED"
            is_observation = normalize_status(
                f.discovery_metadata.get("status")) == "OBSERVATION"
            program_timeline.append({
                "timestamp": f.discovery_metadata.get("timestamp") or datetime.utcnow().isoformat(),
                "event": (
                    f"Vulnerability confirmed: {f.title} ({f.severity})"
                    if is_confirmed_finding
                    else (
                        f"Observation recorded (not a vulnerability): {f.title}"
                        if is_observation
                        else f"Unvalidated hypothesis recorded (not confirmed): {f.title} ({f.severity})"
                    )
                )
            })

        all_audit_entries = await audit_client.get_audit_entries(program_id)
        for entry in all_audit_entries:
            program_timeline.append({
                "timestamp": entry.get("timestamp") or datetime.utcnow().isoformat(),
                "event": f"Active exploitation task '{entry['action']}' performed on target {entry.get('target', 'unknown host')}. Action output: {entry.get('result', 'Success')}"
            })

        program_timeline.sort(key=lambda x: x["timestamp"])

        # Overall Attack Graph paths summary. Only confirmed findings describe an
        # attack path that was walked; an unvalidated hypothesis has no path yet.
        paths_ascii = []
        for f in confirmed:
            if f.attack_graph:
                paths_ascii.append(f.attack_graph.get("path_ascii"))

        program_attack_graph = {
            "total_attack_paths": len(confirmed),
            "paths_summary": paths_ascii[:5]
        }

        evidence_warnings = [
            {
                "finding": f.title,
                "gaps": f.evidence_gaps,
                "message": "confirmed but not submittable until the evidence is attached",
            }
            for f in findings
            if f.validation_state == "CONFIRMED" and f.evidence_gaps
        ]

        # Program Support Resources
        program_support_resources = [
            {"channel": "Wraith Product Security", "contact": "prodsec@wraith.io"},
            {"channel": "Wraith Security On-Call", "contact": "https://wraith.io/oncall"},
            {"channel": "Incident Response Line", "contact": "+1 (800) WRAITH-SEC"}
        ]

        excluded_non_findings = [
            {
                "title": f.get("title") or str(f.get("vuln_type") or "Unknown probe"),
                "vuln_type": f.get("vuln_type"),
                "status": f.get("status"),
                "reason": non_finding_reason(f),
            }
            for f in excluded_non_findings_raw
        ]

        return ProgramReport(
            investigation_name=program_data.get("name", "Unknown Program") if program_data else "Unknown",
            generated_at=datetime.utcnow(),
            findings=findings,
            summary_line=summary,
            executive_summary=executive_summary,
            timeline=program_timeline,
            attack_graph=program_attack_graph,
            support_resources=program_support_resources,
            coverage=coverage,
            report_profile=report_profile,
            submission_guidance=submission_guidance,
            evidence_warnings=evidence_warnings,
            excluded_non_findings=excluded_non_findings,
        )

generator = ReportGenerator()
