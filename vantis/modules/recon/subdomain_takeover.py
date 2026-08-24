"""
Subdomain takeover detection.

A subdomain whose DNS still points at a de-provisioned third-party service
(GitHub Pages, Heroku, S3, Fastly…) can often be re-claimed by an attacker,
who then controls content on that hostname. We detect the tell-tale
"unclaimed service" response fingerprints over HTTP(S).

Runs after recon's subdomain enumeration, reusing the in-scope hosts it found
(ctx.extra_hosts) plus the target host. Detection only — it never registers or
claims anything; it just reports hosts that look takeover-able.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

# service -> signature strings that indicate an unclaimed / dangling target.
FINGERPRINTS: dict[str, list[str]] = {
    "GitHub Pages": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "Bitbucket": ["Repository not found"],
    "Fastly": ["Fastly error: unknown domain"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Surge.sh": ["project not found"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist"],
    "Zendesk": ["Help Center Closed"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "Netlify": ["Not Found - Request ID"],
    "Readthedocs": ["is unknown to Read the Docs"],
    "Unbounce": ["The requested URL was not found on this server"],
    "Wordpress": ["Do you want to register"],
}


class SubdomainTakeoverModule(ScanModule):
    name = "subdomain-takeover"
    category = "recon"
    description = "Detect dangling subdomains pointing at unclaimed third-party services"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()

        candidates = list(dict.fromkeys([self.ctx.target.host, *(self.ctx.extra_hosts or [])]))
        findings: list[Finding] = []

        for host in candidates:
            if not self.ctx.target.is_in_scope(host):
                continue
            for scheme in ("https", "http"):
                resp = client.get(f"{scheme}://{host}", allow_redirects=True)
                if resp is None or not resp.text:
                    continue
                body = resp.text
                hit = next(((svc, sig) for svc, sigs in FINGERPRINTS.items()
                            for sig in sigs if sig in body), None)
                if hit:
                    service, signature = hit
                    findings.append(Finding(
                        module=self.name,
                        title=f"Possible subdomain takeover: {host} ({service})",
                        severity=Severity.HIGH,
                        target=str(self.ctx.target),
                        matched_at=f"{scheme}://{host}",
                        evidence=f"{service} unclaimed-service signature: \"{signature}\"",
                        description=f"{host} appears to point at an unclaimed {service} resource. If the "
                                    "underlying resource can be registered by anyone, an attacker can serve "
                                    "content on this hostname (subdomain takeover).",
                        remediation="Remove the dangling DNS record, or re-claim/re-provision the "
                                    f"{service} resource it points to.",
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))
                    break  # one scheme is enough per host
        return findings
