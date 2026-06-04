import requests

def check_cors(url, session=None):
    findings = []
    s = session or requests.Session()

    test_origins = [
        "https://evil-attacker.com",
        "https://malicious-site.org",
        "null",
    ]

    try:
        for origin in test_origins:
            headers = {"Origin": origin}
            r = s.get(url, headers=headers, timeout=10, verify=False)

            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                findings.append({
                    "check": "CORS Misconfiguration",
                    "severity": "MEDIUM",
                    "detail": "Wildcard CORS policy detected. Any origin can make cross-origin requests.",
                    "evidence": f"Access-Control-Allow-Origin: * returned for origin: {origin}",
                    "remediation": "Replace wildcard with an explicit allowlist of trusted origins.",
                    "owasp": "A05:2021 Security Misconfiguration"
                })
                break

            elif acao == origin:
                severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                detail = "Server reflects arbitrary origin in CORS header."
                if acac.lower() == "true":
                    detail += " Credentials allowed — attacker can make authenticated cross-origin requests."
                findings.append({
                    "check": "CORS Misconfiguration",
                    "severity": severity,
                    "detail": detail,
                    "evidence": f"Access-Control-Allow-Origin: {acao}, Allow-Credentials: {acac or 'not set'}",
                    "remediation": "Validate Origin header against a strict server-side allowlist. Never reflect arbitrary origins.",
                    "owasp": "A05:2021 Security Misconfiguration"
                })
                break

            elif acao == "null" and origin == "null":
                findings.append({
                    "check": "CORS Null Origin Accepted",
                    "severity": "HIGH",
                    "detail": "Server accepts null origin which can be exploited via sandboxed iframes.",
                    "evidence": "Access-Control-Allow-Origin: null accepted",
                    "remediation": "Never allow null as a trusted origin.",
                    "owasp": "A05:2021 Security Misconfiguration"
                })
                break

    except requests.exceptions.RequestException as e:
        pass

    return findings