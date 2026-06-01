import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Missing HSTS header. Site is vulnerable to protocol downgrade attacks.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Missing CSP header. Site is vulnerable to XSS and data injection attacks.",
        "remediation": "Implement a Content Security Policy restricting resource loading."
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Content-Type-Options header. Browser may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options header. Site may be vulnerable to clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Missing Permissions-Policy header. Browser features are unrestricted.",
        "remediation": "Add a Permissions-Policy header restricting access to browser features."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Missing Referrer-Policy header. Sensitive URL data may leak to third parties.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    }
}

def check_security_headers(url, session=None):
    findings = []
    try:
        s = session or requests.Session()
        r = s.get(url, timeout=10, verify=False)
        for header, meta in SECURITY_HEADERS.items():
            if header not in r.headers:
                findings.append({
                    "check": "Missing Security Header",
                    "severity": meta["severity"],
                    "detail": meta["description"],
                    "evidence": f"Header '{header}' absent from response",
                    "remediation": meta["remediation"],
                    "owasp": "A05:2021 Security Misconfiguration"
                })
    except requests.exceptions.RequestException as e:
        findings.append({
            "check": "Connection Error",
            "severity": "INFO",
            "detail": f"Could not connect to target: {e}",
            "evidence": str(e),
            "remediation": "Verify the target URL is accessible.",
            "owasp": "N/A"
        })
    return findings