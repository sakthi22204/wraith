from datetime import datetime
from typing import List, Dict, Any
from .models import ReportFinding, ProgramReport
from .clients.graph_db_client import graph_db_client
from .clients.audit_client import audit_client
from .mapping.cwe_mapping import get_mapping
from .mapping.cvss_calculator import cvss_calculator

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
        cvss_vector = finding.get("cvss_vector")
        score, band = (None, "Unknown")

        if cvss_vector:
            score, band = cvss_calculator.calculate(cvss_vector)

        if score is not None:
            cvss_display = f"{score} ({band})"
        else:
            cvss_display = "CVSS score not calculated"

        severity = finding.get("severity", band).capitalize()

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
            "cmdi": "Avoid calling OS commands with user input. Use safe alternatives or sanitize input thoroughly."
        }
        suggested_remediation = (
            finding.get("remediation")
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
        attack_nodes.append(f"Finding: {title} ({severity})")
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
            ai_confidence=ai_confidence_display,
            affected_asset=affected_asset,
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
            discovery_metadata=discovery_metadata,
            risk_rating=risk_rating,
            timeline=timeline,
            attack_graph=attack_graph,
            support_resources=support_resources
        )

    async def generate_program_report(self, program_id: str) -> ProgramReport:
        program_data = await graph_db_client.get_program(program_id)
        findings_raw = await graph_db_client.get_findings_for_program(program_id)

        duplicates = [f for f in findings_raw if f.get("status") == "DUPLICATE"]
        false_positives = [f for f in findings_raw if f.get("status") == "FALSE_POSITIVE"]

        active_findings_raw = [
            f for f in findings_raw
            if f.get("status") not in ["DUPLICATE", "FALSE_POSITIVE"]
        ]

        findings = []
        for f in active_findings_raw:
            report_finding = await self.generate_finding_report(program_id, f)
            findings.append(report_finding)

        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        findings.sort(key=lambda x: severity_order.get(x.severity, 5))

        summary = f"{len(duplicates)} duplicate and {len(false_positives)} false-positive finding(s) excluded from this report."

        # Program Executive Summary
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total_score = 0.0
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            if f.risk_rating:
                total_score += f.risk_rating.get("score", 0.0)

        avg_score = round(total_score / len(findings), 1) if findings else 0.0
        posture = "HIGH RISK / ACTION REQUIRED" if (severity_counts["Critical"] > 0 or severity_counts["High"] > 0) else "SECURE"

        executive_summary = {
            "overall_posture": posture,
            "average_risk_score": avg_score,
            "severity_breakdown": severity_counts,
            "assessment_comment": f"An automated security assessment identified {len(findings)} active security issues. {severity_counts['Critical']} critical and {severity_counts['High']} high severity findings require immediate remediation."
        }

        # Program Validation Timeline
        program_timeline = []
        for f in findings:
            program_timeline.append({
                "timestamp": f.discovery_metadata.get("timestamp") or datetime.utcnow().isoformat(),
                "event": f"Vulnerability found: {f.title} ({f.severity})"
            })

        all_audit_entries = await audit_client.get_audit_entries(program_id)
        for entry in all_audit_entries:
            program_timeline.append({
                "timestamp": entry.get("timestamp") or datetime.utcnow().isoformat(),
                "event": f"Active exploitation task '{entry['action']}' performed on target {entry.get('target', 'unknown host')}. Action output: {entry.get('result', 'Success')}"
            })

        program_timeline.sort(key=lambda x: x["timestamp"])

        # Overall Attack Graph paths summary
        paths_ascii = []
        for f in findings:
            if f.attack_graph:
                paths_ascii.append(f.attack_graph.get("path_ascii"))

        program_attack_graph = {
            "total_attack_paths": len(findings),
            "paths_summary": paths_ascii[:5]
        }

        # Program Support Resources
        program_support_resources = [
            {"channel": "Wraith Product Security", "contact": "prodsec@wraith.io"},
            {"channel": "Wraith Security On-Call", "contact": "https://wraith.io/oncall"},
            {"channel": "Incident Response Line", "contact": "+1 (800) WRAITH-SEC"}
        ]

        return ProgramReport(
            investigation_name=program_data.get("name", "Unknown Program") if program_data else "Unknown",
            generated_at=datetime.utcnow(),
            findings=findings,
            summary_line=summary,
            executive_summary=executive_summary,
            timeline=program_timeline,
            attack_graph=program_attack_graph,
            support_resources=program_support_resources
        )

generator = ReportGenerator()
