"""
Reflected XSS detection via URL-parameter fuzzing.

Methodology: for each query parameter found on the target page (or a
small default set), inject a unique, harmless canary string containing
HTML metacharacters, then check whether it comes back UNESCAPED in the
response body. This proves the injection point exists without ever
running attacker-controlled JavaScript against a real user — it's a
detection technique, not an exploit/payload delivery mechanism.
"""
from __future__ import annotations

import re
import uuid

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.crawler import InjectionPoint, discover_injection_points, set_param
from vantis.utils.http_client import HttpClient

DEFAULT_PARAMS = ["q", "search", "id", "name", "query", "keyword", "page", "url", "redirect"]


class XssCheckModule(ScanModule):
    name = "reflected-xss"
    category = "web"
    description = "Detect reflected XSS via harmless canary-string reflection testing"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        target = self.ctx.target

        # Test real injection points found by the crawler (target params, links,
        # GET forms). If nothing is discovered, fall back to probing a default
        # parameter list against the exact URL the user pointed at.
        points = discover_injection_points(client, target, self.log, use_browser=self.ctx.browser_crawl)
        if not points:
            points = [InjectionPoint(url=target.url, param=p, source="default") for p in DEFAULT_PARAMS]

        findings: list[Finding] = []

        for point in points[:25]:  # cap for politeness
            param = point.param
            canary = f"vs{uuid.uuid4().hex[:8]}"
            payload = f"\"'><svg id={canary}>"
            test_url = set_param(point.url, param, payload)

            resp = client.get(test_url)
            if resp is None or not resp.text:
                continue

            # Reflected markup only executes when the browser parses the response
            # as HTML. A canary echoed unescaped in a JSON/plain-text API response
            # is NOT XSS in that context, so gate the HIGH finding on the
            # Content-Type (treat a missing type as HTML, the risky default).
            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            served_as_html = content_type == "" or "html" in content_type or "xml" in content_type

            # Look for the canary reflected WITHOUT its HTML metacharacters
            # being escaped (i.e. the raw tag structure survived).
            unescaped_pattern = re.compile(re.escape(f"<svg id={canary}>"))
            if unescaped_pattern.search(resp.text) and served_as_html:
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Reflected XSS in parameter '{param}'",
                        severity=Severity.HIGH,
                        target=str(self.ctx.target),
                        matched_at=test_url,
                        evidence=f"Injected marker reflected unescaped (Content-Type: {content_type or 'unset'}): <svg id={canary}>",
                        description=(
                            f"The '{param}' parameter reflects attacker-controlled input into "
                            "the HTML response without encoding. Confirm manually and check the "
                            "actual response context (attribute vs. body vs. script) before reporting."
                        ),
                        remediation="Context-aware output encoding (HTML-entity encode for body context) or a templating engine with autoescaping.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )
                )
            elif unescaped_pattern.search(resp.text) and not served_as_html:
                # Reflected unescaped but not served as HTML — not exploitable as
                # XSS in this context, but worth noting (could matter if the
                # content type ever changes, or for content sniffing).
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Parameter '{param}' reflected unescaped in non-HTML response",
                        severity=Severity.INFO,
                        target=str(self.ctx.target),
                        matched_at=test_url,
                        evidence=f"Reflected unescaped but Content-Type is '{content_type or 'unset'}', not HTML.",
                        description="Input reflects without encoding, but the response is not served as HTML, so it does not execute as XSS here. Re-check if the endpoint can return HTML.",
                    )
                )
            elif canary in resp.text:
                # Reflected but escaped — worth a low-severity note, not a real finding
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Parameter '{param}' reflected but appears encoded",
                        severity=Severity.INFO,
                        target=str(self.ctx.target),
                        matched_at=test_url,
                        description="Input is reflected but HTML metacharacters seem encoded — likely not exploitable, but worth a manual look at other contexts (JS strings, attributes).",
                    )
                )

        return findings
