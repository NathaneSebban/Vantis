"""
Security header audit — checks for missing/misconfigured headers that
are widely accepted best practice (OWASP Secure Headers Project).
Zero risk of side effects: this is a single GET request.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

REQUIRED_HEADERS = {
    "Strict-Transport-Security": (
        Severity.MEDIUM,
        "HSTS missing — allows protocol downgrade / SSL-stripping attacks on first visit.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
    ),
    "X-Content-Type-Options": (
        Severity.LOW,
        "Missing 'nosniff' — browsers may MIME-sniff responses, enabling some XSS vectors.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "X-Frame-Options": (
        Severity.LOW,
        "No clickjacking protection via legacy header (check CSP frame-ancestors too).",
        "Add 'X-Frame-Options: DENY' or a CSP frame-ancestors directive.",
    ),
    "Content-Security-Policy": (
        Severity.MEDIUM,
        "No Content-Security-Policy — reduces defense-in-depth against XSS.",
        "Define a CSP appropriate to the app (start with report-only mode).",
    ),
    "Referrer-Policy": (
        Severity.INFO,
        "No Referrer-Policy set — full URLs (possibly with tokens) may leak via Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
}

RISKY_HEADER_VALUES = {
    "Access-Control-Allow-Origin": lambda v: v.strip() == "*",
}


class HeadersCheckModule(ScanModule):
    name = "security-headers"
    category = "web"
    description = "Audit HTTP response for missing/misconfigured security headers"

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        resp = client.get(str(self.ctx.target))
        if resp is None:
            return []

        findings: list[Finding] = []

        for header, (severity, desc, remediation) in REQUIRED_HEADERS.items():
            if header not in resp.headers:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Missing security header: {header}",
                        severity=severity,
                        target=str(self.ctx.target),
                        description=desc,
                        remediation=remediation,
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        for header, is_risky in RISKY_HEADER_VALUES.items():
            value = resp.headers.get(header)
            if value and is_risky(value):
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Risky value for {header}",
                        severity=Severity.MEDIUM,
                        target=str(self.ctx.target),
                        evidence=f"{header}: {value}",
                        description="Wildcard CORS allows any origin to read authenticated responses if combined with credentials.",
                        remediation="Restrict Access-Control-Allow-Origin to a known allowlist.",
                    )
                )

        # Cookie flags
        for name, morsel in resp.cookies.items():
            flags_missing = []
            if not morsel.get("secure"):
                flags_missing.append("Secure")
            if not morsel.get("httponly"):
                flags_missing.append("HttpOnly")
            samesite = morsel.get("samesite")
            if not samesite:
                flags_missing.append("SameSite")

            if flags_missing:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Cookie '{name}' missing flag(s): {', '.join(flags_missing)}",
                        severity=Severity.LOW if "HttpOnly" not in flags_missing else Severity.MEDIUM,
                        target=str(self.ctx.target),
                        description="Missing cookie flags increase exposure to XSS-based theft or CSRF.",
                        remediation="Set Secure, HttpOnly and SameSite=Lax/Strict on session cookies.",
                    )
                )

        return findings
