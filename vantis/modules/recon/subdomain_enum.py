"""
Passive subdomain enumeration via Certificate Transparency logs (crt.sh).

Passive = no packets sent to the target itself, only to a public CT log
aggregator. This is why it's safe to run before authorization nuance
questions even come up for the target's own infrastructure, though the
overall scan still requires authorization confirmation.
"""
from __future__ import annotations

import json

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Confidence, Finding, Severity
from vantis.utils.http_client import HttpClient


class SubdomainEnumModule(ScanModule):
    name = "subdomain-enum"
    category = "recon"
    description = "Passive subdomain discovery via crt.sh certificate transparency logs"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        domain = self.ctx.target.host
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        resp = client.get(url)
        if resp is None or resp.status_code != 200:
            self.log("crt.sh unreachable or returned no data")
            return []

        try:
            entries = json.loads(resp.text)
        except ValueError:
            return []

        subdomains: set[str] = set()
        for entry in entries:
            names = entry.get("name_value", "")
            for line in names.splitlines():
                line = line.strip().lstrip("*.").lower()
                # Exact domain or a true subdomain only. A plain endswith(domain)
                # would wrongly match sibling domains owned by others, e.g.
                # "evil<domain>" ends with "<domain>".
                if line == domain or line.endswith("." + domain):
                    subdomains.add(line)

        in_scope = [s for s in subdomains if self.ctx.target.is_in_scope(s)]
        out_of_scope = len(subdomains) - len(in_scope)

        if self.ctx.extra_hosts is None:
            self.ctx.extra_hosts = []
        self.ctx.extra_hosts.extend(sorted(in_scope))

        findings = []
        if in_scope:
            findings.append(
                Finding(
                    module=self.name, confidence=Confidence.HIGH,
                    title=f"{len(in_scope)} subdomain(s) discovered via certificate transparency",
                    severity=Severity.INFO,
                    target=str(self.ctx.target),
                    evidence="\n".join(sorted(in_scope)[:50]),
                    description=(
                        f"Found via crt.sh. {out_of_scope} additional match(es) were "
                        "excluded as out of declared scope."
                        if out_of_scope
                        else "Found via crt.sh public certificate transparency logs."
                    ),
                )
            )
        return findings
