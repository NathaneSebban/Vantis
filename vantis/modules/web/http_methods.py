"""
HTTP method audit (non-destructive).

Reads the methods the server advertises via an OPTIONS request and flags
dangerous ones (PUT, DELETE, PATCH, CONNECT) and TRACE (Cross-Site Tracing).
Only OPTIONS and TRACE are actually sent; no write method is ever issued —
reporting that PUT is *allowed* never means we tried to PUT anything.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

DANGEROUS = {"PUT", "DELETE", "PATCH", "CONNECT"}


class HttpMethodsModule(ScanModule):
    name = "http-methods"
    category = "web"
    description = "Report dangerous HTTP methods advertised/accepted by the server"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        url = str(self.ctx.target)
        findings: list[Finding] = []

        resp = client.request("OPTIONS", url)
        if resp is not None:
            allow = resp.headers.get("Allow", "")
            methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = sorted(methods & DANGEROUS)
            if risky:
                findings.append(Finding(
                    module=self.name,
                    title=f"Dangerous HTTP method(s) advertised: {', '.join(risky)}",
                    severity=Severity.LOW, target=url, matched_at=url,
                    evidence=f"Allow: {allow}",
                    description="The server advertises write/administrative methods. If not intentionally "
                                "exposed and access-controlled, they can allow unauthorized changes.",
                    remediation="Disable unused methods at the web server / reverse proxy; restrict the rest.",
                ))

        # TRACE -> Cross-Site Tracing (can reflect headers/cookies).
        trace = client.request("TRACE", url)
        if trace is not None and trace.status_code == 200 and "TRACE" in (trace.text or "").upper()[:200]:
            findings.append(Finding(
                module=self.name,
                title="HTTP TRACE enabled (Cross-Site Tracing)",
                severity=Severity.LOW, target=url, matched_at=url,
                evidence=f"TRACE -> HTTP {trace.status_code}, request echoed",
                description="TRACE echoes the request and can be abused to read headers/cookies via XST.",
                remediation="Disable the TRACE method on the web server.",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
            ))
        return findings
