"""
CORS misconfiguration detection (active).

The static wildcard case (`Access-Control-Allow-Origin: *`) is already covered
by the security-headers module. The dangerous, easy-to-miss case is a server
that *reflects* an arbitrary request Origin back in Access-Control-Allow-Origin
— especially together with Access-Control-Allow-Credentials: true, which lets
any site read authenticated responses. We detect it by sending a probe Origin
and checking whether it is echoed. Detection only: no data is read.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

PROBE_ORIGIN = "https://vantis-cors-probe.example"


class CorsCheckModule(ScanModule):
    name = "cors-misconfig"
    category = "web"
    description = "Detect reflected-origin / credentialed CORS misconfigurations"

    def _check(self, client: HttpClient, url: str, origin: str) -> Finding | None:
        resp = client.get(url, headers={"Origin": origin})
        if resp is None:
            return None
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").strip().lower() == "true"
        if acao is None:
            return None

        reflected = acao.strip() == origin
        allows_null = acao.strip().lower() == "null" and origin.lower() == "null"

        if (reflected or allows_null) and acac:
            return Finding(
                module=self.name,
                title="CORS: arbitrary origin reflected with credentials",
                severity=Severity.HIGH, target=str(self.ctx.target), matched_at=url,
                evidence=f"Sent Origin: {origin} -> ACAO: {acao}, ACAC: true",
                description="The server reflects an arbitrary Origin and allows credentials, so any "
                            "website can read this app's authenticated responses on a victim's behalf.",
                remediation="Reflect only an allowlisted set of trusted origins, and never combine a "
                            "reflected/`*`/`null` origin with Access-Control-Allow-Credentials: true.",
                references=["https://portswigger.net/web-security/cors"],
            )
        if reflected or allows_null:
            return Finding(
                module=self.name,
                title="CORS: arbitrary origin reflected",
                severity=Severity.MEDIUM, target=str(self.ctx.target), matched_at=url,
                evidence=f"Sent Origin: {origin} -> ACAO: {acao}",
                description="The server reflects an arbitrary Origin. Without credentials the impact is "
                            "lower, but it still weakens the same-origin policy.",
                remediation="Restrict Access-Control-Allow-Origin to a known allowlist.",
                references=["https://portswigger.net/web-security/cors"],
            )
        return None

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        url = self.ctx.target.url
        findings: list[Finding] = []
        seen: set[str] = set()
        for origin in (PROBE_ORIGIN, "null"):
            f = self._check(client, url, origin)
            if f and f.title not in seen:
                seen.add(f.title)
                findings.append(f)
        return findings
