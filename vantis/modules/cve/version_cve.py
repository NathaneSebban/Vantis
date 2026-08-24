"""
Version -> known-CVE mapping.

Parses the software/version disclosed in response headers (Server,
X-Powered-By) and matches it against a curated local knowledge base of
version-constrained CVEs. This is detection by version fingerprint — it flags
that the running version is *known-vulnerable*, it does not attempt any exploit.

The knowledge base is intentionally small and hand-curated (high signal); it is
trivial to extend — add entries to KNOWN_CVES.
"""
from __future__ import annotations

import re

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

# product key -> list of {constraint, cve, severity, name}
# constraints: any of ge/gt/le/lt as dotted-version strings (AND-combined).
KNOWN_CVES: dict[str, list[dict]] = {
    "nginx": [
        {"lt": "1.21.0", "cve": "CVE-2021-23017", "severity": "high",
         "name": "nginx resolver off-by-one heap write (CVE-2021-23017)"},
    ],
    "apache": [
        {"ge": "2.4.49", "le": "2.4.50", "cve": "CVE-2021-41773", "severity": "critical",
         "name": "Apache httpd path traversal / RCE (CVE-2021-41773 / 42013)"},
        {"lt": "2.4.56", "ge": "2.4.0", "cve": "CVE-2023-25690", "severity": "high",
         "name": "Apache httpd mod_proxy HTTP request smuggling (CVE-2023-25690)"},
    ],
    "openssh": [
        {"lt": "9.3", "ge": "8.5", "cve": "CVE-2023-38408", "severity": "high",
         "name": "OpenSSH ssh-agent PKCS#11 RCE (CVE-2023-38408)"},
    ],
    "php": [
        {"lt": "8.1.29", "ge": "8.1.0", "cve": "CVE-2024-4577", "severity": "critical",
         "name": "PHP-CGI argument injection RCE on Windows (CVE-2024-4577)"},
    ],
    "openssl": [
        {"ge": "3.0.0", "lt": "3.0.7", "cve": "CVE-2022-3602", "severity": "high",
         "name": "OpenSSL X.509 punycode buffer overflow (CVE-2022-3602/3786)"},
    ],
}

# header value fragments like "nginx/1.24.0" or "Apache/2.4.49 (Ubuntu)" or "PHP/8.1.2"
_PRODUCT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_+-]*)/(\d+(?:\.\d+){1,3})")
_ALIASES = {"apache": "apache", "httpd": "apache", "nginx": "nginx", "openssh": "openssh",
            "php": "php", "openssl": "openssl"}


def _vtuple(v: str) -> tuple[int, ...]:
    parts = []
    for chunk in v.split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def _satisfies(version: str, c: dict) -> bool:
    v = _vtuple(version)
    if "lt" in c and not (v < _vtuple(c["lt"])):
        return False
    if "le" in c and not (v <= _vtuple(c["le"])):
        return False
    if "gt" in c and not (v > _vtuple(c["gt"])):
        return False
    if "ge" in c and not (v >= _vtuple(c["ge"])):
        return False
    return True


def known_cves_for(product: str, version: str) -> list[dict]:
    """Pure lookup: CVE entries whose constraints the version satisfies."""
    key = _ALIASES.get(product.lower())
    if key is None:
        return []
    return [c for c in KNOWN_CVES.get(key, []) if _satisfies(version, c)]


def products_from_headers(headers: dict) -> list[tuple[str, str]]:
    """Extract (product, version) pairs from Server / X-Powered-By headers."""
    out: list[tuple[str, str]] = []
    for h in ("Server", "X-Powered-By", "X-AspNet-Version"):
        value = headers.get(h) or ""
        for product, version in _PRODUCT_RE.findall(value):
            out.append((product, version))
    return out


class VersionCveModule(ScanModule):
    name = "version-cve"
    category = "cve"
    description = "Map disclosed software versions to known CVEs (local knowledge base)"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        resp = client.get(str(self.ctx.target))
        if resp is None:
            return []

        findings: list[Finding] = []
        seen: set[str] = set()
        for product, version in products_from_headers(dict(resp.headers)):
            for c in known_cves_for(product, version):
                if c["cve"] in seen:
                    continue
                seen.add(c["cve"])
                findings.append(Finding(
                    module=self.name,
                    title=c["name"],
                    severity=Severity(c["severity"]),
                    target=str(self.ctx.target),
                    matched_at=str(self.ctx.target),
                    evidence=f"{product}/{version} matches {c['cve']}",
                    description=f"The disclosed version {product}/{version} is affected by {c['cve']}. "
                                "Confirm the exact build and patch level before reporting.",
                    remediation=f"Upgrade {product} to a fixed release.",
                    references=[f"https://nvd.nist.gov/vuln/detail/{c['cve']}"],
                ))
        return findings
