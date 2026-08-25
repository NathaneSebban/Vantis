"""
Server-Side Template Injection detection (non-destructive).

Injects a harmless arithmetic expression in several template syntaxes and
checks whether the *product* appears in the response — proving the expression
was evaluated server-side, not merely reflected. A large, unusual product is
used so a coincidental match is essentially impossible, and the baseline is
checked so a page that already contains the number is not a false positive.
No code is executed beyond the arithmetic probe.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.crawler import InjectionPoint, discover_injection_points, set_param

DEFAULT_PARAMS = ["q", "search", "name", "id", "page", "query", "message", "template", "input"]

# 1337 * 1338 = 1788906 — distinctive, unlikely to occur by chance.
_A, _B = 1337, 1338
PRODUCT = str(_A * _B)
PAYLOADS = [
    "{{%d*%d}}" % (_A, _B),      # Jinja2, Twig, Nunjucks
    "${%d*%d}" % (_A, _B),       # FreeMarker, Thymeleaf, JSP EL
    "#{%d*%d}" % (_A, _B),       # Ruby (Slim/ERB-ish), JSF
    "<%%= %d*%d %%>" % (_A, _B),  # ERB
    "*{%d*%d}" % (_A, _B),       # Thymeleaf
]


class SstiCheckModule(ScanModule):
    name = "ssti-detect"
    category = "web"
    description = "Detect server-side template injection via arithmetic evaluation"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        target = self.ctx.target

        discovered = discover_injection_points(client, target, self.log, use_browser=self.ctx.browser_crawl)
        points = list(discovered)
        for p in DEFAULT_PARAMS:
            points.append(InjectionPoint(url=target.url, param=p, source="default"))

        findings: list[Finding] = []
        seen: set[str] = set()

        for point in points[:25]:
            if point.param in seen:
                continue
            # If the page already contains the product, we can't trust a match.
            base = client.get(set_param(point.url, point.param, "1"))
            if base is not None and PRODUCT in (base.text or ""):
                continue

            for payload in PAYLOADS:
                resp = client.get(set_param(point.url, point.param, payload))
                if resp is None or not resp.text:
                    continue
                if PRODUCT in resp.text:
                    seen.add(point.param)
                    findings.append(Finding(
                        module=self.name,
                        title=f"Server-side template injection in parameter '{point.param}'",
                        severity=Severity.HIGH, target=str(target),
                        matched_at=set_param(point.url, point.param, payload),
                        evidence=f"Payload {payload!r} evaluated to {PRODUCT} in the response",
                        description=f"The '{point.param}' parameter is evaluated by a server-side template "
                                    "engine — an arithmetic probe was computed server-side. SSTI often leads "
                                    "to remote code execution.",
                        remediation="Do not pass user input into template source; use a sandboxed, "
                                    "logic-less templating approach and pass data as context variables only.",
                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                    ))
                    break
        return findings
