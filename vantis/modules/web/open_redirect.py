"""
Open redirect detection (non-destructive).

Injects a unique off-site canary into redirect-style parameters (discovered by
the crawler plus a default list) and checks whether the server issues an HTTP
redirect whose Location points at the canary host. Redirects are NOT followed —
we only read the Location header, so nothing off-site is ever requested.
"""
from __future__ import annotations

from urllib.parse import urlparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.crawler import InjectionPoint, discover_injection_points, set_param
from vantis.utils.http_client import HttpClient

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "return_url",
                   "dest", "destination", "continue", "redirect_uri", "redir", "r", "u", "to"]

CANARY_HOST = "vantis-openredirect.example"
CANARY_URL = f"https://{CANARY_HOST}/"


class OpenRedirectModule(ScanModule):
    name = "open-redirect"
    category = "web"
    description = "Detect open redirects via off-site canary in redirect parameters"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        target = self.ctx.target

        # Prefer redirect-named params among discovered points; always also test
        # the default redirect param list against the target URL.
        discovered = discover_injection_points(client, target, self.log, use_browser=self.ctx.browser_crawl)
        points: list[InjectionPoint] = [p for p in discovered if p.param.lower() in REDIRECT_PARAMS]
        for p in REDIRECT_PARAMS:
            points.append(InjectionPoint(url=target.url, param=p, source="default"))

        findings: list[Finding] = []
        seen: set[str] = set()

        for point in points[:25]:
            test_url = set_param(point.url, point.param, CANARY_URL)
            key = f"{point.param}"
            if key in seen:
                continue
            # Do NOT follow the redirect — just inspect the Location header.
            resp = client.get(test_url, allow_redirects=False)
            if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
                continue
            location = resp.headers.get("Location", "")
            if urlparse(location).hostname == CANARY_HOST:
                seen.add(key)
                findings.append(Finding(
                    module=self.name,
                    title=f"Open redirect via parameter '{point.param}'",
                    severity=Severity.MEDIUM, target=str(target), matched_at=test_url,
                    evidence=f"HTTP {resp.status_code} -> Location: {location}",
                    description=f"The '{point.param}' parameter controls the redirect destination and "
                                "accepts an arbitrary external URL, enabling phishing and OAuth token theft.",
                    remediation="Allow only relative paths or an allowlist of destinations; never redirect "
                                "to a user-supplied absolute URL.",
                    references=["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                ))
        return findings
