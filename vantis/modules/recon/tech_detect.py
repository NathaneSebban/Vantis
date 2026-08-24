"""
Basic technology fingerprinting from HTTP response headers, cookies,
and simple HTML body signatures. Intentionally lightweight compared to
a full Wappalyzer ruleset — good enough to flag "what's running here"
and, importantly, versions that reveal outdated/EOL software.
"""
from __future__ import annotations

import re

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

HEADER_SIGNATURES = {
    "Server": {
        r"nginx/([\d.]+)": "nginx",
        r"Apache/([\d.]+)": "Apache",
        r"Microsoft-IIS/([\d.]+)": "IIS",
        r"cloudflare": "Cloudflare",
    },
    "X-Powered-By": {
        r"PHP/([\d.]+)": "PHP",
        r"Express": "Express.js",
        r"ASP\.NET": "ASP.NET",
    },
}

COOKIE_SIGNATURES = {
    "wordpress_": "WordPress",
    "PHPSESSID": "PHP",
    "laravel_session": "Laravel",
    "csrftoken": "Django",
    "JSESSIONID": "Java/JSP",
}

BODY_SIGNATURES = {
    r"wp-content|wp-includes": "WordPress",
    r"Drupal.settings": "Drupal",
    r"/sites/default/files": "Drupal",
    r"csrf-token.*Laravel|laravel_session": "Laravel",
    r"__NEXT_DATA__": "Next.js",
    r"ng-version": "Angular",
    r"data-reactroot|react-dom": "React",
}


class TechDetectModule(ScanModule):
    name = "tech-detect"
    category = "recon"
    description = "Fingerprint web technologies from headers/cookies/body"

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        resp = client.get(str(self.ctx.target))
        if resp is None:
            return []

        detected: set[str] = set()
        versioned: list[str] = []

        for header, patterns in HEADER_SIGNATURES.items():
            value = resp.headers.get(header, "")
            for pattern, tech in patterns.items():
                m = re.search(pattern, value, re.IGNORECASE)
                if m:
                    detected.add(tech)
                    if m.groups():
                        versioned.append(f"{tech} {m.group(1)}")

        for cookie_name, tech in COOKIE_SIGNATURES.items():
            if any(cookie_name.lower() in c.lower() for c in resp.cookies.keys()):
                detected.add(tech)

        body_sample = resp.text[:20000] if resp.text else ""
        for pattern, tech in BODY_SIGNATURES.items():
            if re.search(pattern, body_sample, re.IGNORECASE):
                detected.add(tech)

        findings: list[Finding] = []
        if detected:
            findings.append(
                Finding(
                    module=self.name,
                    title="Technology stack fingerprinted",
                    severity=Severity.INFO,
                    target=str(self.ctx.target),
                    evidence=", ".join(sorted(detected)),
                )
            )
        if versioned:
            findings.append(
                Finding(
                    module=self.name,
                    title="Software version(s) disclosed in headers",
                    severity=Severity.LOW,
                    target=str(self.ctx.target),
                    evidence=", ".join(versioned),
                    description=(
                        "Exact version numbers leaking in response headers make it trivial "
                        "for an attacker to check for known CVEs against that exact build."
                    ),
                    remediation="Suppress version info in Server/X-Powered-By headers.",
                )
            )
        return findings
