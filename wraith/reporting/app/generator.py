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
        title = f"{vuln_type.upper()} in {finding.get('description', 'Unknown Asset')[:50]}"

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

        # 8. Evidence
        evidence = finding.get("evidence") or "No raw evidence captured"

        # 6. Steps to Reproduce
        tool_info = await graph_db_client.get_discovering_tool(program_id, finding["id"])
        tool_name = tool_info.get("name", "security tool") if tool_info else "automated scan"

        steps = (
            f"Reconstructed steps (best effort):\n"
            f"1. Target the affected asset: {affected_asset}\n"
            f"2. Use {tool_name} to perform a {vuln_type} check.\n"
            f"3. Observe the following result: {description}"
        )

        # 7. Exploit / PoC
        audit_entries = await audit_client.get_audit_entries(program_id, target=target_details.get("host") if target_details else None)
        relevant_audit = [
            e for e in audit_entries
            if vuln_type.lower() in e["action"].lower() or (tool_name.lower() in e["action"].lower() and e["action"].lower() != "run_nmap_scan")
        ]

        if relevant_audit:
            poc = f"Recorded exploit attempt via {relevant_audit[0]['action']}:\n"
            poc += f"Result: {relevant_audit[0].get('result')}"
        else:
            poc = f"No active exploitation was performed for this finding — validated via {tool_name} only"

        # 9. Business Impact
        impact_map = {
            "critical": "Complete compromise of the affected system, potentially leading to unauthorized data access and full administrative control.",
            "high": "Serious impact on the confidentiality, integrity, or availability of the system and its data.",
            "medium": "Limited impact on the system, which could still lead to disclosure of sensitive information or unauthorized actions.",
            "low": "Minimal impact, often requiring specific conditions to be exploitable or affecting non-sensitive data.",
            "info": "Informational finding with no direct security impact but may provide useful context for further attacks."
        }
        business_impact = impact_map.get(severity.lower(), "Potential security risk to the organization's assets and reputation.")

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
        suggested_remediation = remediation_map.get(vuln_type.lower(), "Follow industry best practices for securing the affected component and addressing the identified vulnerability class.")

        # 11. Metadata
        program_data = await graph_db_client.get_program(program_id)
        discovery_metadata = {
            "timestamp": finding.get("discovered_at"),
            "tool": tool_name,
            "program": program_data.get("name", "Unknown Program") if program_data else "Unknown",
            "confidence": finding.get("confidence"),
            "status": finding.get("status")
        }

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
            discovery_metadata=discovery_metadata
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

        return ProgramReport(
            investigation_name=program_data.get("name", "Unknown Program") if program_data else "Unknown",
            generated_at=datetime.utcnow(),
            findings=findings,
            summary_line=summary
        )

generator = ReportGenerator()
