from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any, Set

# The graph's statuses that mean "someone proved this". Anything else -- still
# UNCONFIRMED, actively REFUTED, or left INCONCLUSIVE -- is a lead, not a
# result, and must not carry weight in a score.
#
# HUMAN_CONFIRMED is excluded: there is no human review phase, and an executed
# proof (AI_VALIDATED) or independent corroboration (CORROBORATED) is the whole
# vocabulary of confirmation.
VALIDATED_STATUSES = frozenset({"AI_VALIDATED", "CORROBORATED"})
from .schemas import (
    AssessmentCoverage,
    AssessmentReport,
    TargetPriority,
    CVECorrelation,
    ValidationTask,
)

# A wordlist sweep records every path the server was asked about and answered.
# A single-page app answers all of them identically, so those endpoints are
# guesses that happened to get a response -- not proof the path exists, and
# certainly not proof of what software serves them. Technology fingerprints
# must come from somewhere the target itself produced the string: response
# banners, or a URL found in the target's own HTML.
CONTENT_DERIVED_SOURCES = {
    "katana", "gau", "hakrawler", "waybackurls", "linkfinder",
    "gospider", "httpx", "secretfinder", "trufflehog", "gittools",
}


# Finding states that count as a confirmed vulnerability, in the graph's own
# vocabulary. AI_VALIDATED is where an executed proof lands; CORROBORATED is a
# second independent source agreeing. HUMAN_CONFIRMED is deliberately absent --
# confirmation comes from evidence, not from a sign-off.
_CONFIRMED_STATUSES = frozenset({"AI_VALIDATED", "CORROBORATED"})

# Validation outcomes that mean a request was actually sent and graded. The
# BLOCKED_* outcomes are refusals -- scope, killswitch, rate limit or an
# execution error -- and count as neither executed nor inconclusive.
_EXECUTED_VALIDATION_OUTCOMES = frozenset({"CONFIRMED", "REFUTED", "INCONCLUSIVE"})


def _path_segments(url: str):
    """The path's segments, lowercased, with no scheme/host or query.

    Substring matching over the whole URL is how `/api` came to mean "REST API"
    for a target with no API at all: the letters "api" also occur in
    "/capital", "/rapid", and every path under "/graphql/apiary".
    """
    raw = (url or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        path = parsed.path
    elif raw.startswith("//"):
        # Scheme-relative, so urlparse reads the first segment as the host.
        path = parsed.path
    else:
        # A bare or root-relative path. There is no authority here, and
        # urlparse's netloc guess would eat the first real segment.
        path = parsed.path
    return [s for s in path.lower().split("/") if s]


def _technologies_from_url(url: str) -> Set[str]:
    """Technologies implied by a path, matched segment-wise.

    Requires an actual path segment to be the marker, so "/wp-content" counts
    but "/my-wp-content-mirror" does not.
    """
    found: Set[str] = set()
    segments = _path_segments(url)
    if not segments:
        return found
    if any(seg in ("wp-content", "wp-includes") for seg in segments):
        found.add("WordPress")
    if "api" in segments or any(
        seg in ("v1", "v2", "v3") and i and segments[i - 1] == "api"
        for i, seg in enumerate(segments)
    ):
        found.add("REST API")
    return found


class AssessmentEngine:
    @staticmethod
    def generate_report(investigation_id: str, graph_data: Dict[str, Any]) -> AssessmentReport:
        nodes = graph_data.get("nodes", [])
        links = graph_data.get("links", [])

        # Counts
        hosts = [n for n in nodes if "Host" in n.get("labels", [])]
        services = [n for n in nodes if "Service" in n.get("labels", [])]
        endpoints = [n for n in nodes if "Endpoint" in n.get("labels", [])]
        findings = [n for n in nodes if "Finding" in n.get("labels", [])]
        validations = [n for n in nodes if "ValidationAttempt" in n.get("labels", [])]

        # 1. Technologies Analysis
        technologies = set()
        for s in services:
            tech_name = s["properties"].get("name", "")
            if tech_name:
                technologies.add(tech_name)

        # Check for WordPress or CMS in URLs. Only URLs the target itself
        # produced count: a path that came out of a wordlist is a question we
        # asked, not an answer the target gave.
        for e in endpoints:
            url = e["properties"].get("url", "")
            if not url:
                continue
            source = str(e["properties"].get("source_tool", "")).lower()
            if source and source not in CONTENT_DERIVED_SOURCES:
                continue
            technologies |= _technologies_from_url(url)

        # 2. Correlate CVEs
        correlated_cves = []
        for s in services:
            tech_name = s["properties"].get("name", "").lower()
            if "ssh" in tech_name:
                correlated_cves.append(CVECorrelation(
                    cve_id="CVE-2023-38408",
                    title="OpenSSH Agent Forwarding Remote Code Execution",
                    cvss_score=9.8,
                    affected_service=s["properties"].get("name", "SSH")
                ))
            if "nginx" in tech_name or "apache" in tech_name:
                correlated_cves.append(CVECorrelation(
                    cve_id="CVE-2021-23017",
                    title="Nginx Resolver 1-byte Heap Off-by-one Vulnerability",
                    cvss_score=8.1,
                    affected_service=s["properties"].get("name", "Web Server")
                ))

        # 3. Findings Summary
        #
        # Every Finding node is counted, whatever its status. A finding that was
        # actively disproved still happened; a finding nobody tested is still
        # untested, and reporting those two the same way as a confirmed one is
        # how a graph full of candidates reads as a graph full of problems.
        findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f["properties"].get("severity", "info").lower()
            if sev in findings_summary:
                findings_summary[sev] += 1
            else:
                findings_summary["info"] += 1

        # Risk is a different question from inventory. It weights what was
        # demonstrated, so it counts only findings whose status says someone
        # actually proved them. Scoring a REFUTED finding as live risk is the
        # error the severity floor exists to prevent one layer up; scoring an
        # UNCONFIRMED one compounds it.
        validated = [
            f for f in findings
            if str(f["properties"].get("status", "")).upper() in VALIDATED_STATUSES
        ]
        risk_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in validated:
            sev = str(f["properties"].get("severity", "info")).lower()
            if sev in risk_summary:
                risk_summary[sev] += 1

        # 4. Calculate Risk Score (Base of 2.0, adding up to 10.0 based on findings)
        risk_score = 2.0
        risk_score += risk_summary["critical"] * 2.0
        risk_score += risk_summary["high"] * 1.5
        risk_score += risk_summary["medium"] * 0.8
        risk_score += risk_summary["low"] * 0.3
        risk_score = min(10.0, max(1.0, risk_score))

        # 5. Prioritize Targets
        prioritized_targets = []
        for e in endpoints:
            url = e["properties"].get("url", "").lower()
            host_val = "unknown"
            # Try to find connected host
            for link in links:
                if link["target"] == e["id"]:
                    source_id = link["source"]
                    for n in nodes:
                        if n["id"] == source_id and "Host" in n["labels"]:
                            host_val = n["properties"].get("value", "unknown")
                            break

            score = 1.0
            reason = "Standard endpoint discovered."
            if "admin" in url or "login" in url or "config" in url:
                score += 4.5
                reason = "Sensitive URL path (admin/login/config) exposed."
            elif "api" in url or "v1" in url:
                score += 3.0
                reason = "API endpoint exposed."

            prioritized_targets.append(TargetPriority(
                target_id=e["id"],
                host=host_val,
                type="Endpoint",
                risk_score=score,
                reason=reason
            ))

        # Sort prioritized targets
        prioritized_targets.sort(key=lambda x: x.risk_score, reverse=True)
        prioritized_targets = prioritized_targets[:10]

        # 6. Generate Validation Plan (Attack Surface Summary & Recommended Validation Order)
        validation_plan = []
        step_num = 1
        for t in prioritized_targets:
            if t.risk_score >= 5.0:
                validation_plan.append(ValidationTask(
                    step=step_num,
                    target=t.host,
                    action="run_nuclei_scan",
                    reason=f"Verify sensitive URL exposed at {t.host}. Reason: {t.reason}"
                ))
                step_num += 1
            elif "api" in t.reason.lower():
                validation_plan.append(ValidationTask(
                    step=step_num,
                    target=t.host,
                    action="run_sqlmap",
                    reason=f"Scan API parameters for injection. Target host: {t.host}"
                ))
                step_num += 1

        if not validation_plan:
            # Fallback default plan
            target_val = "localhost"
            if hosts:
                target_val = hosts[0]["properties"].get("value", "localhost")
            validation_plan.append(ValidationTask(
                step=1,
                target=target_val,
                action="run_nmap_scan",
                reason="Default baseline port scan on available scope domains."
            ))

        # Coverage: what this report was actually able to look at.
        coverage = AssessmentEngine._build_coverage(endpoints, findings, validations)

        # Output payload
        return AssessmentReport(
            investigation_id=investigation_id,
            risk_score=risk_score,
            technologies=list(technologies),
            hosts_count=len(hosts),
            services_count=len(services),
            endpoints_count=len(endpoints),
            findings_summary={k.capitalize(): v for k, v in findings_summary.items() if k != "info"},
            prioritized_targets=prioritized_targets,
            correlated_cves=correlated_cves,
            validation_plan=validation_plan,
            generated_at=datetime.utcnow(),
            coverage=coverage,
        )

    # Path prefixes that identify an API surface. Kept in step with the route
    # prefixes the recon orchestrator extracts from frontend bundles, so "we
    # found no API routes" means the same thing on both sides of the pipeline.
    _API_PREFIXES = ("/api", "/rest", "/v1", "/v2", "/graphql")

    @staticmethod
    def _build_coverage(endpoints: List[Dict[str, Any]],
                        findings: List[Dict[str, Any]],
                        validations: List[Dict[str, Any]] = None) -> AssessmentCoverage:
        """Describe the evidence behind the score, and name what is missing.

        Every counter here is read out of the graph. Nothing is inferred or
        assumed: where the graph cannot answer a question (no candidate node is
        ever written), that is recorded as a gap rather than reported as a zero,
        so an empty report cannot be mistaken for a clean bill of health.
        """
        validations = validations or []
        urls = [(e.get("properties") or {}).get("url", "") or "" for e in endpoints]
        js_bundles = [u for u in urls if u.lower().split("?")[0].endswith(".js")]
        api_endpoints = [
            u for u in urls
            if any(p in urlparse(u).path.lower() for p in AssessmentEngine._API_PREFIXES)
        ]

        statuses = [
            str((f.get("properties") or {}).get("status", "") or "").upper()
            for f in findings
        ]
        # The graph's FindingStatus vocabulary, not the validation runner's
        # outcome vocabulary. A graded validation that lands CONFIRMED is
        # written as AI_VALIDATED. Counting only the runner's word would report
        # zero confirmed findings for an investigation that has them.
        confirmed = _CONFIRMED_STATUSES
        families = sorted({
            str((f.get("properties") or {}).get("vuln_type", "") or "").strip()
            for f in findings
        } - {""})

        # Validation attempts are written to the graph as ValidationAttempt
        # nodes. This used to report len(findings) as "validations executed",
        # which counted findings, not tests -- and counted INCONCLUSIVE as a
        # finding status the graph never stores, so it was always zero. Both
        # numbers told the reader nothing about how much was actually tried.
        outcomes = [
            str((v.get("properties") or {}).get("outcome", "") or "").upper()
            for v in validations
        ]
        # A blocked attempt was refused by a gate and never reached the target;
        # counting it as executed would overstate what was tested, which is the
        # whole reason this block exists.
        executed = [o for o in outcomes if o in _EXECUTED_VALIDATION_OUTCOMES]

        coverage = AssessmentCoverage(
            endpoints_discovered=len(endpoints),
            javascript_bundles=len(js_bundles),
            api_endpoints=len(api_endpoints),
            findings_recorded=len(findings),
            candidate_families=families,
            validations_run=len(executed),
            validations_inconclusive=executed.count("INCONCLUSIVE"),
            findings_confirmed=sum(1 for s in statuses if s in confirmed),
        )

        # Gaps, in the order they compound: nothing reached, then nothing
        # recognised as an application surface, then nothing tried.
        if coverage.endpoints_discovered == 0:
            coverage.gaps.append(
                "No endpoints reached the graph; recon produced nothing to assess.")
        else:
            if coverage.javascript_bundles == 0:
                coverage.gaps.append(
                    "No JavaScript bundle was read, so routes held in a "
                    "single-page app's client code are undiscovered.")
            if coverage.api_endpoints == 0:
                coverage.gaps.append(
                    "No API routes were discovered among the known endpoints; "
                    "a backend behind an unparsed client bundle would be "
                    "invisible to this assessment.")
            if not families:
                coverage.gaps.append(
                    "No hypotheses were raised from the discovered endpoints, "
                    "so nothing was tested beyond reachability.")
            if coverage.findings_confirmed == 0 and coverage.validations_run == 0:
                coverage.gaps.append(
                    "No validation was executed; absence of findings here is "
                    "absence of evidence, not evidence of absence.")
        return coverage
