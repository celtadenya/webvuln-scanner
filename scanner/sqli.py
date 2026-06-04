import requests
import urllib.parse

SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "pg_query",
    "sqlite_",
    "ora-",
    "microsoft ole db provider for sql server",
    "odbc drivers error",
]

def check_sqli(url, session=None):
    findings = []
    s = session or requests.Session()

    # Parse URL for existing parameters
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        # Try common parameter names if none exist
        test_params = ["id", "user", "search", "query", "page", "item"]
        for param in test_params:
            for payload in SQLI_PAYLOADS:
                test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                try:
                    r = s.get(test_url, timeout=10, verify=False)
                    body = r.text.lower()
                    for error in SQLI_ERRORS:
                        if error in body:
                            findings.append({
                                "check": "SQL Injection",
                                "severity": "CRITICAL",
                                "detail": f"Possible SQL injection via parameter '{param}'. Server returned a database error.",
                                "evidence": f"GET {test_url} returned error pattern: '{error}'",
                                "remediation": "Use parameterised queries or prepared statements. Never concatenate user input into SQL queries.",
                                "owasp": "A03:2021 Injection"
                            })
                            return findings
                except requests.exceptions.RequestException:
                    pass
    else:
        # Inject into existing parameters
        for param in params:
            for payload in SQLI_PAYLOADS:
                new_params = params.copy()
                new_params[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(new_params, doseq=True)}"
                try:
                    r = s.get(test_url, timeout=10, verify=False)
                    body = r.text.lower()
                    for error in SQLI_ERRORS:
                        if error in body:
                            findings.append({
                                "check": "SQL Injection",
                                "severity": "CRITICAL",
                                "detail": f"SQL injection confirmed via parameter '{param}' with payload: {payload}",
                                "evidence": f"GET {test_url} returned error pattern: '{error}'",
                                "remediation": "Use parameterised queries or prepared statements. Never concatenate user input into SQL queries.",
                                "owasp": "A03:2021 Injection"
                            })
                            return findings
                except requests.exceptions.RequestException:
                    pass

    return findings