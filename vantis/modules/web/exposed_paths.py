"""
Checks for common sensitive files/paths left exposed on the web root.
This category of bug (exposed .git, .env, backups, debug endpoints)
is consistently one of the highest-value, lowest-effort finds in real
bug bounty programs.
"""
from __future__ import annotations

import secrets

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.utils.http_client import HttpClient

# path -> (severity, description, content-check substring or None)
CHECKS: dict[str, tuple[Severity, str, str | None]] = {
    ".git/config": (Severity.CRITICAL, "Exposed .git directory can leak full source code and history.", "[core]"),
    ".git/HEAD": (Severity.CRITICAL, "Exposed .git directory can leak full source code and history.", "ref:"),
    ".env": (Severity.CRITICAL, "Exposed .env often contains database credentials, API keys, secrets.", None),
    ".env.local": (Severity.CRITICAL, "Exposed .env often contains database credentials, API keys, secrets.", None),
    "wp-config.php.bak": (Severity.CRITICAL, "Backup of WordPress config may leak DB credentials.", None),
    "config.php.bak": (Severity.HIGH, "Backup config file may leak credentials.", None),
    ".DS_Store": (Severity.LOW, "Reveals local directory structure/filenames.", None),
    "docker-compose.yml": (Severity.HIGH, "May expose internal service topology and sometimes credentials.", None),
    ".well-known/security.txt": (Severity.INFO, "Good practice indicator, not a vulnerability.", None),
    "phpinfo.php": (Severity.HIGH, "phpinfo() output leaks detailed server/environment configuration.", "PHP Version"),
    "server-status": (Severity.MEDIUM, "Apache server-status can leak internal request/traffic details.", None),
    "actuator/env": (Severity.HIGH, "Spring Boot Actuator env endpoint can leak configuration/secrets.", None),
    "actuator/health": (Severity.INFO, "Spring Boot Actuator exposed; check other actuator endpoints.", None),
    "swagger-ui.html": (Severity.LOW, "Exposed API documentation UI — check if it should be public.", None),
    "api/swagger.json": (Severity.LOW, "Exposed OpenAPI spec — review for sensitive endpoints.", None),
    "backup.zip": (Severity.HIGH, "Exposed backup archive.", None),
    "backup.sql": (Severity.CRITICAL, "Exposed database dump.", None),
}


class ExposedPathsModule(ScanModule):
    name = "exposed-paths"
    category = "web"
    description = "Probe for commonly-exposed sensitive files and debug endpoints"

    def run(self) -> list[Finding]:
        client = HttpClient(timeout=self.ctx.http_timeout, delay=self.ctx.rate_limit_delay)
        base = str(self.ctx.target).rstrip("/")

        # Catch-all / soft-404 baseline: many servers (SPAs with
        # `try_files ... /index.html`, custom 404 handlers) answer 200 with the
        # SAME page for ANY URL. Without this, every probe below would "match"
        # and produce a wall of false positives. We fingerprint the response to
        # a path that cannot exist, and later treat any probe that looks like
        # that page as "not really there" — unless we have a positive content
        # signal (must_contain) proving it's the real file.
        probe = client.get(f"{base}/vantis-nonexistent-{secrets.token_hex(8)}")
        catch_all = probe is not None and probe.status_code == 200 and bool(probe.text)
        baseline_len = len(probe.text) if catch_all else 0

        findings: list[Finding] = []

        for path, (severity, description, must_contain) in CHECKS.items():
            url = f"{base}/{path}"
            resp = client.get(url)
            if resp is None or resp.status_code != 200:
                continue
            if not resp.text or len(resp.text.strip()) == 0:
                continue
            if must_contain and must_contain not in resp.text:
                continue
            if len(resp.text) > 2_000_000:
                continue

            # Reject catch-all responses: if the server serves a default page
            # for unknown paths and this response is ~the same size as that
            # page, it's the default page, not the sensitive file. Skipped only
            # when we have no positive content signal (must_contain is None) —
            # a validated match (e.g. .git/config containing "[core]") is kept.
            if must_contain is None and catch_all:
                if abs(len(resp.text) - baseline_len) <= max(48, int(baseline_len * 0.02)):
                    self.log(f"skip {path}: looks like catch-all page ({len(resp.text)}B ~ baseline {baseline_len}B)")
                    continue

            content_type = resp.headers.get("Content-Type", "?").split(";")[0].strip()
            findings.append(
                Finding(
                    module=self.name,
                    title=f"Exposed sensitive path: /{path}",
                    severity=severity,
                    target=base,
                    matched_at=url,
                    description=description,
                    # Record what we actually observed so a finding can be audited.
                    evidence=f"HTTP {resp.status_code}, {len(resp.text)} bytes, Content-Type: {content_type}",
                    remediation="Remove the file from the web root or block access at the web server/reverse proxy level.",
                )
            )

        return findings
