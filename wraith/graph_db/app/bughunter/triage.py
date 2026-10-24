"""BugHunter 7-question gate for graph_db."""
from typing import Dict, Any, Tuple

class TriageGate:
    NEVER_SUBMIT = [
        "missing_csp", "missing_hsts", "missing_spf", "missing_dkim", "missing_dmarc",
        "graphql_introspection_only", "banner_version_disclosure_without_cve_exploit",
        "clickjacking_on_nonsensitive_pages", "open_redirect_alone_without_chain",
        "xss_alert_only_without_impact", "source_map_only"
    ]
    
    def validate_finding(self, finding: Dict[str, Any]) -> Tuple[bool, str]:
        vuln_type = str(finding.get("vuln_type", "")).lower()
        poc_request = finding.get("poc_request", "")
        poc_response = finding.get("poc_response", "")
        severity = str(finding.get("severity", "")).lower()
        description = str(finding.get("description", "")).lower()
        
        # Q1: need concrete PoC
        if not poc_request and not finding.get("evidence"):
            return False, "Q1 FAIL: Need concrete PoC request"
        if not poc_response and not finding.get("evidence"):
            return False, "Q1 FAIL: Need concrete evidence/response"
        
        # Q7: never submit
        for bad in self.NEVER_SUBMIT:
            if bad.replace("_", "-") in vuln_type or bad.replace("_", " ") in description:
                # allow if chained
                if "chain" not in description and "bypass" not in description:
                    return False, f"Q7 FAIL: {bad} typically not reportable alone"
        
        # Q6: proof of impact
        if vuln_type in ["xss"]:
            if "cookie" not in poc_response.lower() and "session" not in poc_response.lower() and "alert(document.domain)" not in poc_response:
                if "alert(" in poc_response and len(poc_response) < 200:  # simple alert
                    return False, "Q6 FAIL: XSS needs proof of impact beyond simple alert()"
        elif vuln_type in ["idor"]:
            if "other user" not in description and "other_user" not in str(finding):
                return False, "Q6 FAIL: IDOR needs proof of accessing OTHER user's data"
        
        return True, "PASS"

triage_gate = TriageGate()
