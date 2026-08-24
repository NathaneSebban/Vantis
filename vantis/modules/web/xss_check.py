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
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

DEFAULT_PARAMS = ["q", "search", "id", "name", "query", "keyword", "page", "url", "redirect"]


class XssCheckModule(ScanModule):
    name = "reflected-xss"
    category = "web"
    description = "Detect reflected XSS via harmless canary-string reflection testing"

    def _build_test_url(self, base_url: str, param: str, canary: str) -> str:
        parsed = urlparse(base_url)
        qs = parse_qs(parsed.query)
        qs[param] = [canary]
        new_query = urlencode(qs, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        base_url = str(self.ctx.target)

        # Discover existing query params on the landing page, fall back to a default list
        parsed = urlparse(base_url)
        existing_params = list(parse_qs(parsed.query).keys())
        params_to_test = existing_params or DEFAULT_PARAMS

        findings: list[Finding] = []

        for param in params_to_test[:15]:  # cap for politeness
            canary = f"vs{uuid.uuid4().hex[:8]}"
            payload = f"\"'><svg id={canary}>"
            test_url = self._build_test_url(base_url, param, payload)

            resp = client.get(test_url)
            if resp is None or not resp.text:
                continue

            # Look for the canary reflected WITHOUT its HTML metacharacters
            # being escaped (i.e. the raw tag structure survived).
            unescaped_pattern = re.compile(re.escape(f"<svg id={canary}>"))
            if unescaped_pattern.search(resp.text):
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Reflected XSS in parameter '{param}'",
                        severity=Severity.HIGH,
                        target=base_url,
                        matched_at=test_url,
                        evidence=f"Injected marker reflected unescaped: <svg id={canary}>",
                        description=(
                            f"The '{param}' parameter reflects attacker-controlled input into "
                            "the HTML response without encoding. Confirm manually and check the "
                            "actual response context (attribute vs. body vs. script) before reporting."
                        ),
                        remediation="Context-aware output encoding (HTML-entity encode for body context) or a templating engine with autoescaping.",
                        references=["https://owasp.org/www-community/attacks/xss/"],
                    )
                )
            elif canary in resp.text:
                # Reflected but escaped — worth a low-severity note, not a real finding
                findings.append(
                    Finding(
                        module=self.name,
                        title=f"Parameter '{param}' reflected but appears encoded",
                        severity=Severity.INFO,
                        target=base_url,
                        matched_at=test_url,
                        description="Input is reflected but HTML metacharacters seem encoded — likely not exploitable, but worth a manual look at other contexts (JS strings, attributes).",
                    )
                )

        return findings
