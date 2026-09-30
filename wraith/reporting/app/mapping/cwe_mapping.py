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
    },
    # Categories the Kali toolchain actually emits. Without these, a metrics or
    # header finding rendered as "Unknown - Unknown" in the report.
    "info disclosure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "information disclosure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "api exposure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "missing security header": {
        "cwe_id": "CWE-693",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    },
    "security misconfiguration": {
        "cwe_id": "CWE-16",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "exposed debug endpoint": {
        "cwe_id": "CWE-489",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    # The deterministic hypothesis rules (Phase 1) emit these long-form types.
    # Map them so generated findings render real CWE/OWASP labels rather than
    # "Unknown - Unknown".
    "sql injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "cors misconfiguration": {
        "cwe_id": "CWE-942",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "cors": {
        "cwe_id": "CWE-942",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "missing security headers": {
        "cwe_id": "CWE-693",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    },
    "host header injection": {
        "cwe_id": "CWE-644",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    },
    "open redirect": {
        "cwe_id": "CWE-601",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    },
    "account enumeration": {
        "cwe_id": "CWE-204",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "cross-site request forgery": {
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    },
    "weak jwt handling": {
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    # The deterministic hypothesis rules (Phase 1.5) emit these types.
    "mass assignment": {
        "cwe_id": "CWE-915",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "business logic flaw": {
        "cwe_id": "CWE-840",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "unrestricted file upload": {
        "cwe_id": "CWE-434",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "graphql introspection": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "graphql alias over-fetch": {
        "cwe_id": "CWE-400",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    },
    # The Phase 1.6 concurrency harness emits this type.
    "race condition / toctou": {
        "cwe_id": "CWE-367",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "race condition": {
        "cwe_id": "CWE-362",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    # The threshold harness emits this type: absence of a rate limit is
    # CWE-307 (improper restriction of excessive authentication attempts), which
    # is what brute force and credential stuffing actually abuse.
    "missing rate limiting": {
        "cwe_id": "CWE-307",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    }
}

def get_mapping(vuln_type: str):
    return CWE_MAPPING.get(vuln_type.lower(), {
        "cwe_id": "Unknown",
        "owasp_category": "Unknown",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    })
