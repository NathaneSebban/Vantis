"""
Nuclei-style YAML template engine for known-CVE / misconfiguration
detection.

Design principle: templates are DETECTION signatures only (a GET/HEAD
request + a matcher on status code / header / body regex). They never
encode multi-step exploitation, payload delivery, or anything that
would cause a state change on the target. This mirrors how Nuclei's
own official "technologies"/"exposures" templates behave, as opposed
to its (much more tightly gated) exploit templates.

Template format (YAML):

    id: example-template
    info:
      name: Human readable name
      severity: medium        # info|low|medium|high|critical
      cve: CVE-2023-XXXXX      # optional
      description: ...
      reference:
        - https://...
    request:
      method: GET
      path: /some/path         # relative to target base URL
    matchers:
      status: [200]             # optional, list of acceptable codes
      body_contains: ["some marker"]     # optional, ALL must match
      header:                    # optional: {header_name: substring}
        Server: "nginx/1.18"
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from vantis.core.report import Confidence, Finding, Severity
from vantis.utils.http_client import HttpClient


@dataclass
class Template:
    id: str
    name: str
    severity: Severity
    method: str
    path: str
    description: str = ""
    cve: str | None = None
    references: list[str] | None = None
    matcher_status: list[int] | None = None
    matcher_body_contains: list[str] | None = None
    matcher_header: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Template":
        info = data.get("info", {})
        request = data.get("request", {})
        matchers = data.get("matchers", {})
        return cls(
            id=data["id"],
            name=info.get("name", data["id"]),
            severity=Severity(info.get("severity", "info")),
            description=info.get("description", ""),
            cve=info.get("cve"),
            references=info.get("reference", []),
            method=request.get("method", "GET").upper(),
            path=request.get("path", "/"),
            matcher_status=matchers.get("status"),
            matcher_body_contains=matchers.get("body_contains"),
            matcher_header=matchers.get("header"),
        )

    def matches(self, status_code: int, body: str, headers: dict) -> bool:
        if self.matcher_status is not None and status_code not in self.matcher_status:
            return False
        if self.matcher_body_contains:
            if not all(marker in (body or "") for marker in self.matcher_body_contains):
                return False
        if self.matcher_header:
            for hname, needle in self.matcher_header.items():
                actual = headers.get(hname, "")
                if needle not in actual:
                    return False
        # A template with no matchers at all should never auto-match
        if self.matcher_status is None and not self.matcher_body_contains and not self.matcher_header:
            return False
        return True


def load_templates(templates_dir: str | Path) -> list[Template]:
    templates: list[Template] = []
    for path in sorted(Path(templates_dir).glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            templates.append(Template.from_dict(data))
        except Exception as e:  # noqa: BLE001
            print(f"[!] Failed to load template {path}: {e}")
    return templates


def run_templates(
    base_url: str,
    templates: list[Template],
    client: HttpClient,
) -> list[Finding]:
    findings: list[Finding] = []

    # Catch-all / soft-404 baseline: fetch a path that cannot exist. On servers
    # that answer 200 with the same page for ANY URL (SPAs, custom soft-404s), a
    # template whose markers also appear on that page would false-positive — so
    # any template that ALSO matches this baseline response is suppressed below.
    import secrets

    base = base_url.rstrip("/")
    baseline = client.get(f"{base}/vantis-nonexistent-{secrets.token_hex(8)}")
    baseline_data = (
        (baseline.status_code, baseline.text or "", dict(baseline.headers))
        if baseline is not None else None
    )

    for tmpl in templates:
        url = base + tmpl.path
        resp = client.get(url) if tmpl.method == "GET" else client.session.request(
            tmpl.method, url, timeout=client.timeout
        )
        if resp is None:
            continue

        # If the template also matches the catch-all page, the "match" is the
        # server's default response, not the real resource — skip it.
        if baseline_data is not None and tmpl.matches(*baseline_data):
            continue

        if tmpl.matches(resp.status_code, resp.text, dict(resp.headers)):
            findings.append(
                Finding(
                    module=f"cve-template:{tmpl.id}",
                    title=tmpl.name,
                    severity=tmpl.severity,
                    target=base_url,
                    matched_at=url,
                    description=tmpl.description + (f" (CVE: {tmpl.cve})" if tmpl.cve else ""),
                    references=tmpl.references or [],
                )
            )

    return findings
