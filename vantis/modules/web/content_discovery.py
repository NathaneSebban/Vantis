"""
Content discovery (path brute-forcing).

Probes a built-in wordlist of common directories and endpoints and reports the
ones that actually exist. Reuses the same soft-404/catch-all baseline as the
exposed-paths module so a server that answers 200 for everything doesn't
produce a wall of false hits.

- 200 (and unlike the catch-all page)  -> discovered
- 401 / 403                            -> exists but access-restricted (useful recon)
- everything else                      -> ignored

Detection only: it requests paths with GET and reports what responds; it never
submits data or tries to authenticate.
"""
from __future__ import annotations

import secrets

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Confidence, Finding, Severity

# Common directories/endpoints. Kept deliberately focused (fast + polite);
# the sensitive-file set lives in the exposed-paths module.
WORDLIST = [
    "admin", "administrator", "login", "logout", "signin", "dashboard", "account",
    "api", "api/v1", "api/v2", "graphql", "graphiql", "rest", "soap",
    "swagger", "swagger-ui", "api-docs", "openapi.json", "docs", "redoc",
    "config", "settings", "setup", "install", "installer", "upgrade",
    "backup", "backups", "old", "bak", "tmp", "temp", "test", "tests", "dev", "staging",
    "uploads", "upload", "files", "file", "media", "assets", "static", "download", "downloads",
    "private", "internal", "secret", "hidden", "console", "debug", "trace",
    "phpmyadmin", "adminer", "adminer.php", "pma", "wp-admin", "wp-login.php",
    "server-info", "server-status", "status", "health", "healthz", "metrics", "actuator",
    "robots.txt", "sitemap.xml", "crossdomain.xml", ".well-known/security.txt",
    "user", "users", "profile", "register", "cart", "checkout", "search",
    "cgi-bin", "shell", "cmd", "portal", "manager", "management", "monitor",
]

# Paths where mere existence is more interesting than average.
SENSITIVE = {"admin", "administrator", "phpmyadmin", "adminer", "adminer.php", "pma",
             "wp-admin", "graphql", "actuator", "console", "manager", "management",
             "debug", "server-status", "metrics"}


class ContentDiscoveryModule(ScanModule):
    name = "content-discovery"
    category = "web"
    description = "Brute-force common paths/endpoints (wordlist) with soft-404 filtering"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        base = str(self.ctx.target).rstrip("/")

        # Catch-all baseline (same idea as exposed-paths): fingerprint the page
        # a non-existent path returns, then ignore probes that look like it.
        probe = client.get(f"{base}/vantis-nonexistent-{secrets.token_hex(8)}", allow_redirects=False)
        catch_all = probe is not None and probe.status_code == 200 and bool(probe.text)
        baseline_len = len(probe.text) if (catch_all and probe and probe.text) else 0

        findings: list[Finding] = []
        seen: set[str] = set()

        for path in WORDLIST:
            if path in seen:
                continue
            seen.add(path)
            url = f"{base}/{path}"
            resp = client.get(url, allow_redirects=False)
            if resp is None:
                continue

            code = resp.status_code
            if code in (401, 403):
                findings.append(Finding(
                    module=self.name, confidence=Confidence.HIGH, owasp="A05:2021", cwe="CWE-200",
                    title=f"Access-restricted path exists: /{path}",
                    severity=Severity.INFO, target=base, matched_at=url,
                    evidence=f"HTTP {code}",
                    description="The path exists but is protected — useful for mapping the attack surface.",
                ))
                continue

            if code != 200 or not resp.text:
                continue
            # Skip catch-all default pages.
            if catch_all and abs(len(resp.text) - baseline_len) <= max(48, int(baseline_len * 0.02)):
                continue

            sensitive = path.split("/")[0] in SENSITIVE or path in SENSITIVE
            ctype = resp.headers.get("Content-Type", "?").split(";")[0].strip()
            findings.append(Finding(
                module=self.name, confidence=Confidence.HIGH, owasp="A05:2021", cwe="CWE-200",
                title=f"Discovered path: /{path}",
                severity=Severity.LOW if sensitive else Severity.INFO,
                target=base, matched_at=url,
                evidence=f"HTTP {code}, {len(resp.text)} bytes, Content-Type: {ctype}",
                description=("A potentially sensitive endpoint is reachable — review whether it should be public."
                             if sensitive else "Reachable path discovered via wordlist."),
                remediation="Restrict or remove endpoints that should not be publicly accessible." if sensitive else "",
            ))

        return findings
