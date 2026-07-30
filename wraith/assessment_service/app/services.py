from datetime import datetime
from typing import List, Dict, Any
from .schemas import AssessmentReport, TargetPriority, CVECorrelation, ValidationTask

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

        # 1. Technologies Analysis
        technologies = set()
        for s in services:
            tech_name = s["properties"].get("name", "")
            if tech_name:
                technologies.add(tech_name)

        # Check for WordPress or CMS in URLs
        for e in endpoints:
            url = e["properties"].get("url", "").lower()
            if "wp-content" in url or "wp-includes" in url:
                technologies.add("WordPress")
            if "api" in url or "v1" in url:
                technologies.add("REST API")

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
        findings_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f["properties"].get("severity", "info").lower()
            if sev in findings_summary:
                findings_summary[sev] += 1
            else:
                findings_summary["info"] += 1

        # 4. Calculate Risk Score (Base of 2.0, adding up to 10.0 based on findings)
        risk_score = 2.0
        risk_score += findings_summary["critical"] * 2.0
        risk_score += findings_summary["high"] * 1.5
        risk_score += findings_summary["medium"] * 0.8
        risk_score += findings_summary["low"] * 0.3
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
            generated_at=datetime.utcnow()
        )
