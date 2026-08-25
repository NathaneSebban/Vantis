"""
Path traversal / Local File Inclusion detection (non-destructive).

Injects canonical traversal sequences into discovered parameters and looks for
the world-readable /etc/passwd signature (or the Windows win.ini marker) in the
response — the standard, universally-accepted LFI *detection* signal. It reads
only these fixed marker files to confirm the bug; it never dumps arbitrary
files, which would cross into exploitation.
"""
from __future__ import annotations

import re

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.crawler import InjectionPoint, discover_injection_points, set_param

DEFAULT_PARAMS = ["file", "page", "path", "template", "doc", "document", "folder",
                  "include", "inc", "view", "content", "name", "download"]

PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../../../windows/win.ini",
]

_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_WININI_RE = re.compile(r"\[extensions\]|\[fonts\]", re.IGNORECASE)


class PathTraversalModule(ScanModule):
    name = "path-traversal"
    category = "web"
    description = "Detect path traversal / LFI via /etc/passwd and win.ini markers"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        target = self.ctx.target

        discovered = discover_injection_points(client, target, self.log, use_browser=self.ctx.browser_crawl)
        points = [p for p in discovered if p.param.lower() in DEFAULT_PARAMS]
        for p in DEFAULT_PARAMS:
            points.append(InjectionPoint(url=target.url, param=p, source="default"))

        findings: list[Finding] = []
        seen: set[str] = set()

        for point in points[:25]:
            if point.param in seen:
                continue
            # Baseline: the markers must NOT already be present for a benign value.
            base = client.get(set_param(point.url, point.param, "1"))
            base_text = (base.text or "") if base else ""
            if _PASSWD_RE.search(base_text) or _WININI_RE.search(base_text):
                continue

            for payload in PAYLOADS:
                resp = client.get(set_param(point.url, point.param, payload))
                if resp is None or not resp.text:
                    continue
                if _PASSWD_RE.search(resp.text) or _WININI_RE.search(resp.text):
                    seen.add(point.param)
                    marker = "/etc/passwd" if _PASSWD_RE.search(resp.text) else "windows/win.ini"
                    findings.append(Finding(
                        module=self.name,
                        title=f"Path traversal / LFI in parameter '{point.param}'",
                        severity=Severity.HIGH, target=str(target),
                        matched_at=set_param(point.url, point.param, payload),
                        evidence=f"Traversal payload returned {marker} contents",
                        description=f"The '{point.param}' parameter is vulnerable to path traversal: a "
                                    f"traversal sequence caused {marker} to be read into the response.",
                        remediation="Never build file paths from user input; use an allowlist of identifiers "
                                    "and canonicalize/validate any path before use.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    ))
                    break
        return findings
