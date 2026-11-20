import re
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
    # The recon-driven deterministic rules emit "Information Exposure" (the
    # confidential-document probe), not the "disclosure" wording above.
    "information exposure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    # CWE-209 is the specific descendant for a stack trace / framework error
    # page that discloses internals to an unauthenticated caller.
    "error message disclosure": {
        "cwe_id": "CWE-209",
        "owasp_category": "A05:2021-Security Misconfiguration",
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
    "sql injection (boolean-blind)": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "sql injection (union-based)": {
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
    "jwt algorithm confusion": {
        "cwe_id": "CWE-347",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    # The deterministic hypothesis rules (Phase 1.5) emit these types.
    "mass assignment": {
        "cwe_id": "CWE-915",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    # The campaign files IDOR as the family name, not the "idor" slug.
    "broken access control": {
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
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
    },
    # The deterministic login-bypass rule emits this type. A tautology that
    # yields a session token is an authentication failure, not a parsing quirk.
    "authentication bypass": {
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    # Unauthenticated data routes (feedback, addresses, cards) expose personal
    # data directly; CWE-359 is the PII-specific descendant of CWE-200.
    "pii exposure": {
        "cwe_id": "CWE-359",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    # Skill-pack and playbook families. A report must never render
    # "Unknown - Unknown", so every vuln_type a pack can decide has an entry.
    "api documentation exposure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "agent instruction override": {
        "cwe_id": "CWE-1426",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
    },
    "clickjacking": {
        "cwe_id": "CWE-1021",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"
    },
    "credential spray feasible": {
        "cwe_id": "CWE-307",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    },
    "cross-site scripting": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "html injection": {
        "cwe_id": "CWE-80",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "exposed docker api": {
        "cwe_id": "CWE-306",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    },
    "exposed search service": {
        "cwe_id": "CWE-306",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "exposed terraform state": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "graphql authorization bypass": {
        "cwe_id": "CWE-639",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    },
    "http request smuggling": {
        "cwe_id": "CWE-444",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "improper access control": {
        "cwe_id": "CWE-284",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
    },
    "injection canary": {
        "cwe_id": "CWE-74",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    },
    # Nuclei template names reach the report verbatim ("Public Swagger API -
    # Detect"). The base name carries the weakness; the suffix is the template
    # action, so the lookup strips it and this entry answers for all actions.
    "public swagger api": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "monitoring endpoint exposure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "nosql injection": {
        "cwe_id": "CWE-943",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "path traversal": {
        "cwe_id": "CWE-22",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "prototype pollution": {
        "cwe_id": "CWE-1321",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "reset token disclosed": {
        "cwe_id": "CWE-640",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "sql injection (time-based)": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "sensitive file exposure": {
        "cwe_id": "CWE-538",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "server-side request forgery": {
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "server-side template injection": {
        "cwe_id": "CWE-1336",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "source code exposure": {
        "cwe_id": "CWE-540",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "unauthenticated mcp server": {
        "cwe_id": "CWE-306",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "web cache poisoning": {
        "cwe_id": "CWE-349",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "websocket authentication bypass": {
        "cwe_id": "CWE-306",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "xml external entity": {
        "cwe_id": "CWE-611",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "exposed-backup": {
        "cwe_id": "CWE-530",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "exposed-config": {
        "cwe_id": "CWE-538",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "exposed-secrets": {
        "cwe_id": "CWE-798",
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "exposed-source-code": {
        "cwe_id": "CWE-540",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "graphql-introspection": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "info-disclosure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    # Scanner/template slugs (nuclei ids, recon rule names) reach the report as
    # the vuln_type verbatim. They name the same classes as the human-readable
    # keys above, so map them to the same CWE/OWASP rather than rendering the
    # weakness as "Unknown - Unknown".
    "swagger-api": {
        "cwe_id": "CWE-200",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    },
    "http-missing-security-headers": {
        "cwe_id": "CWE-693",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    },
    "open-proxy-internal": {
        "cwe_id": "CWE-441",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
    },
    "sensitive data exposure": {
        "cwe_id": "CWE-200",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    },
    "business logic": {
        "cwe_id": "CWE-840",
        "owasp_category": "A04:2021-Insecure Design",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"
    },
    "authentication bypass retest": {
        "cwe_id": "CWE-287",
        "owasp_category": "A07:2021-Identification and Authentication Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "ldap injection": {
        "cwe_id": "CWE-90",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "ldap-injection": {
        "cwe_id": "CWE-90",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "xpath injection": {
        "cwe_id": "CWE-643",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "xpath-injection": {
        "cwe_id": "CWE-643",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "graphql injection": {
        "cwe_id": "CWE-74",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "graphql-injection": {
        "cwe_id": "CWE-74",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "orm injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "orm-hql injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "hql injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "jpql injection": {
        "cwe_id": "CWE-89",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "argument injection": {
        "cwe_id": "CWE-88",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "argument-injection": {
        "cwe_id": "CWE-88",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "code injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "code-injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "eval injection": {
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "eval-injection": {
        "cwe_id": "CWE-95",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "client-side template injection": {
        "cwe_id": "CWE-1336",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
    },
    "client template injection": {
        "cwe_id": "CWE-1336",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"
    },
    "expression language injection": {
        "cwe_id": "CWE-917",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "ognl injection": {
        "cwe_id": "CWE-917",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "el injection": {
        "cwe_id": "CWE-917",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "deserialization injection": {
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "deserialization-injection": {
        "cwe_id": "CWE-502",
        "owasp_category": "A08:2021-Software and Data Integrity Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "crlf injection": {
        "cwe_id": "CWE-113",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "crlf-injection": {
        "cwe_id": "CWE-113",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "http response splitting": {
        "cwe_id": "CWE-113",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "response splitting": {
        "cwe_id": "CWE-113",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "generic xml injection": {
        "cwe_id": "CWE-91",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "xml injection": {
        "cwe_id": "CWE-91",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "xml-injection": {
        "cwe_id": "CWE-91",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    },
    "ssi injection": {
        "cwe_id": "CWE-97",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "ssi-injection": {
        "cwe_id": "CWE-97",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "latex injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "latex-injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "log injection": {
        "cwe_id": "CWE-117",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    "log-injection": {
        "cwe_id": "CWE-117",
        "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    "dll injection": {
        "cwe_id": "CWE-427",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "dll-injection": {
        "cwe_id": "CWE-427",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "shared library injection": {
        "cwe_id": "CWE-427",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "process injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "process-injection": {
        "cwe_id": "CWE-94",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
    },
    "browser js execution": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "browser javascript execution": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "oob interaction": {
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "oob-interaction": {
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    },
    "smtp header injection": {
        "cwe_id": "CWE-93",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    "smtp-header-injection": {
        "cwe_id": "CWE-93",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    "mail header injection": {
        "cwe_id": "CWE-93",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"
    },
    "csv formula injection": {
        "cwe_id": "CWE-1236",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "csv injection": {
        "cwe_id": "CWE-1236",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "formula injection": {
        "cwe_id": "CWE-1236",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "dom clobbering": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "dom-clobbering": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "css injection": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "css-injection": {
        "cwe_id": "CWE-79",
        "owasp_category": "A03:2021-Injection",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    },
    "websocket csrf": {
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "websocket cswsh": {
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    },
    "cross site websocket hijacking": {
        "cwe_id": "CWE-352",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    }
}

# The scanner and validation layers use family names that do not always match
# the compact keys above (``Stored XSS`` vs ``xss``, ``Command Injection`` vs
# ``cmdi``). Normalise the common aliases before the exact lookup so a report
# names the weakness class instead of rendering ``Unknown - Unknown``.
_MAPPING_ALIASES = {
    "stored xss": "xss",
    "reflected xss": "xss",
    "dom xss": "xss",
    "persistent xss": "xss",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "local file inclusion": "lfi",
    "path traversal": "lfi",
    "blind sql injection": "sql injection (boolean-blind)",
    "boolean-blind sql injection": "sql injection (boolean-blind)",
    "sql injection (boolean blind)": "sql injection (boolean-blind)",
}


def get_mapping(vuln_type: str):
    """CWE/OWASP entry for an emitted vuln type.

    Recon observations keep the scanner template name ("Public Swagger API -
    Detect"), so a matching map entry is not enough on its own: strip the
    template-action suffix and retry before falling back to Unknown.
    """
    key = str(vuln_type or "").strip().lower()
    mapping = CWE_MAPPING.get(key)
    if mapping is None:
        key = _MAPPING_ALIASES.get(key, key)
        mapping = CWE_MAPPING.get(key)
    if mapping is None:
        key = re.sub(r"\s*-\s*(?:detect|matcher|request|response|template)$", "", key)
        key = _MAPPING_ALIASES.get(key, key)
        mapping = CWE_MAPPING.get(key)
    return mapping or {
        "cwe_id": "Unknown",
        "owasp_category": "Unknown",
        "cvss_template": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    }
