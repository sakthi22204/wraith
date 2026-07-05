CWE_MAPPING = {
    "sqli": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "xss": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "ssrf": {
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "idor": {
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    },
    "jwt": {
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "lfi": {
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "ssti": {
        "cwe_id": "CWE-1336",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "xxe": {
        "cwe_id": "CWE-611",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "cmdi": {
        "cwe_id": "CWE-77",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
}

def get_mapping(vuln_type: str):
    return CWE_MAPPING.get(vuln_type.lower(), {
        "cwe_id": "Unknown",
        "owasp_category": "Unknown",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    })
