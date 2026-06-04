# WebVuln Scanner

An automated web application vulnerability scanner that detects OWASP Top 10 security issues and generates structured reports.

Built by [Celta Denya](https://github.com/celtadenya) - MSc Cybersecurity (Ethical Hacking), Coventry University.

## What It Detects

| Check | OWASP ID | Severity |
|---|---|---|
| Missing security headers (HSTS, CSP, X-Frame-Options) | A05:2021 | LOW to HIGH |
| SQL Injection (error-based, parameter fuzzing) | A03:2021 | CRITICAL |
| Reflected XSS (parameter injection) | A03:2021 | HIGH |
| CORS misconfiguration (wildcard, reflected origin, null origin) | A05:2021 | MEDIUM to CRITICAL |

## Quick Start

Install dependencies and run against any target:

    pip3 install -r requirements.txt
    python3 main.py https://target.com
    python3 main.py https://target.com --output report.json

## Example Output

Scanned https://httpbin.org and found 7 real vulnerabilities including a CRITICAL CORS misconfiguration where the server reflects arbitrary origins with credentials allowed. An attacker can make authenticated cross-origin requests from any domain.
<img width="847" height="419" alt="Screenshot 2026-06-04 at 23 09 58" src="https://github.com/user-attachments/assets/8340ff26-5268-4d8c-b9a7-1e3e79cd6dc7" />
<img width="676" height="456" alt="Screenshot 2026-06-04 at 23 10 10" src="https://github.com/user-attachments/assets/cc27bfbc-f19b-4f87-8377-afeda2d6c22a" />
<img width="859" height="422" alt="Screenshot 2026-06-04 at 23 10 24" src="https://github.com/user-attachments/assets/4d513e25-5add-4aa6-9b37-3fc4fec4e63d" />


## Project Structure

    webvuln-scanner/
    ├── main.py          - Main runner and CLI
    ├── scanner/
    │   ├── headers.py   - Security header checks
    │   ├── sqli.py      - SQL injection detection
    │   ├── xss.py       - XSS detection
    │   └── cors.py      - CORS misconfiguration checks
    ├── reports/         - JSON report output
    └── requirements.txt - Dependencies

## Roadmap

- Broken authentication detection
- IDOR checks
- PDF report generation
- Sensitive file exposure (.env, .git, config)
- GitHub Actions CI/CD integration

## Legal Notice

For authorised security testing only. Only scan targets you own or have explicit written permission to test.
