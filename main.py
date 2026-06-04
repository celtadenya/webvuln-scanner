#!/usr/bin/env python3
"""
WebVuln Scanner - Automated Web Application Vulnerability Scanner
Author: Celta Denya Hadinata Wijaya
GitHub: github.com/celtadenya/webvuln-scanner

Scans web applications for OWASP Top 10 vulnerabilities.
"""

import requests
import argparse
import json
import time
import sys
import urllib3

from scanner.headers import check_security_headers
from scanner.sqli import check_sqli
from scanner.xss import check_xss
from scanner.cors import check_cors

# Suppress SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colours
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ╔══════════════════════════════════════════════╗
  ║         WEBVULN SCANNER v1.0.0               ║
  ║   Automated OWASP Top 10 Vulnerability Scan  ║
  ║   github.com/celtadenya/webvuln-scanner      ║
  ╚══════════════════════════════════════════════╝
{RESET}"""

def severity_color(s):
    return {
        "CRITICAL": RED + BOLD,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": CYAN,
        "INFO": CYAN,
    }.get(s, RESET)

def print_finding(i, f):
    sc = severity_color(f["severity"])
    print(f"\n  [{i}] {sc}{f['severity']}{RESET} — {BOLD}{f['check']}{RESET}")
    print(f"      OWASP:      {f['owasp']}")
    print(f"      Detail:     {f['detail']}")
    print(f"      Evidence:   {CYAN}{f['evidence']}{RESET}")
    print(f"      Fix:        {GREEN}{f['remediation']}{RESET}")

def print_summary(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\n  {'SEVERITY SUMMARY'}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = counts[sev]
        if count:
            bar = "█" * count
            print(f"  {severity_color(sev)}{sev:<10}{RESET}  {bar} ({count})")

def export_json(target, findings, path):
    data = {
        "target": target,
        "total_findings": len(findings),
        "findings": findings
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  {GREEN}JSON report exported to: {path}{RESET}")

def run_scan(target, output=None):
    print(BANNER)
    print(f"  {BOLD}Target:{RESET} {target}")
    print(f"  {BOLD}Checks:{RESET} Security Headers, SQL Injection, XSS, CORS")
    print(f"\n  Scanning...\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "WebVulnScanner/1.0 (github.com/celtadenya/webvuln-scanner)"
    })

    all_findings = []
    start = time.time()

    checks = [
        ("Security Headers", check_security_headers),
        ("SQL Injection",    check_sqli),
        ("XSS",             check_xss),
        ("CORS",            check_cors),
    ]

    for name, fn in checks:
        print(f"  {CYAN}▶{RESET} Running: {name}...", end=" ", flush=True)
        findings = fn(target, session)
        all_findings.extend(findings)
        status = f"{RED}{len(findings)} issue(s){RESET}" if findings else f"{GREEN}clean{RESET}"
        print(status)

    duration = time.time() - start

    print(f"\n{'═'*60}")
    print(f"{BOLD}  SCAN COMPLETE — {target}{RESET}")
    print(f"  Duration: {duration:.2f}s  |  Total findings: {len(all_findings)}")
    print(f"{'═'*60}")

    if not all_findings:
        print(f"\n  {GREEN}No issues detected.{RESET}\n")
        return

    print_summary(all_findings)

    print(f"\n  DETAILED FINDINGS")
    print(f"  {'─'*56}")
    for i, f in enumerate(all_findings, 1):
        print_finding(i, f)

    print(f"\n{'═'*60}\n")

    if output:
        export_json(target, all_findings, output)

def main():
    parser = argparse.ArgumentParser(
        description="WebVuln Scanner — OWASP Top 10 Web Vulnerability Scanner",
        epilog="Example: python main.py http://testphp.vulnweb.com --output report.json"
    )
    parser.add_argument("target", help="Target URL to scan (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("--output", "-o", help="Export findings to JSON file", default=None)
    args = parser.parse_args()

    run_scan(args.target, args.output)

if __name__ == "__main__":
    main()