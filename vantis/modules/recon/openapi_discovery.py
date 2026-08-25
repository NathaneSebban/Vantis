"""
Surfaces OpenAPI/Swagger spec discovery as a visible finding.

The spec itself is also consumed internally by the shared crawler
(utils/openapi_crawler.py, wired into discover_injection_points) to feed exact
endpoint/parameter knowledge to every injection-testing module. This module's
job is purely to make that discovery visible in the report — an exposed API
spec is itself worth flagging (it maps the entire attack surface for anyone
who finds it) and its endpoint count is useful recon context.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Confidence, Finding, Severity
from vantis.utils.openapi_crawler import discover_openapi


class OpenApiDiscoveryModule(ScanModule):
    name = "openapi-discovery"
    category = "recon"
    description = "Detect an exposed OpenAPI/Swagger spec and enumerate its endpoints"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        spec, url = discover_openapi(client, self.ctx.target, self.log)
        if spec is None:
            return []

        paths = spec.get("paths", {})
        methods = sum(
            1 for item in paths.values() if isinstance(item, dict)
            for k in item if k in ("get", "post", "put", "delete", "patch", "head", "options")
        )
        title_field = spec.get("info", {}).get("title") if isinstance(spec.get("info"), dict) else None

        return [Finding(
            module=self.name, confidence=Confidence.HIGH, owasp="A05:2021", cwe="CWE-200",
            title="OpenAPI/Swagger specification exposed",
            severity=Severity.INFO,
            target=str(self.ctx.target),
            matched_at=url,
            evidence=f"{len(paths)} path(s), {methods} operation(s)" + (f", title: {title_field}" if title_field else ""),
            description="An OpenAPI/Swagger spec is publicly reachable, fully documenting the API surface "
                        "(every endpoint, method and parameter). Useful for testing, but also for an attacker — "
                        "confirm this is intentional for a public API.",
            remediation="If the API is not meant to be public, restrict access to the spec document (and "
                        "ideally the API itself) to authorized users/networks.",
        )]
