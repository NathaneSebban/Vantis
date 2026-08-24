"""
Target representation and scope validation.

A Target wraps a domain/URL/IP and enforces that every module only
touches hosts that are explicitly declared in-scope. This is the
mechanism that prevents a module from accidentally (or carelessly)
testing something the user never authorized.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value))


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class Target:
    """A single authorized scan target.

    raw: what the user typed (URL, bare domain, or IP)
    scope: list of hostnames/domains/IPs/CIDRs this target is allowed
           to expand into (e.g. subdomain enum results). Defaults to
           the target itself plus its subdomains.
    """

    raw: str
    scope: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        parsed = urlparse(self.raw if "://" in self.raw else f"http://{self.raw}")
        host = parsed.hostname or self.raw

        if not (_is_valid_hostname(host) or _is_valid_ip(host)):
            raise ValueError(f"'{self.raw}' does not look like a valid host, domain or IP")

        self.host = host
        self.scheme = parsed.scheme or "http"
        self.port = parsed.port
        self.base_url = f"{self.scheme}://{host}" + (f":{self.port}" if self.port else "")

        # Preserve the path and query the user actually pointed at, so
        # parameter-testing modules (xss, sqli) can probe the real endpoint —
        # not just the origin. str(target) stays the origin for modules that
        # build paths relative to the web root (exposed-paths, cve templates).
        self.path = parsed.path or ""
        self.query = parsed.query or ""
        self.url = self.base_url + self.path + (f"?{self.query}" if self.query else "")

        if not self.scope:
            self.scope = [host]

    def is_in_scope(self, candidate_host: str) -> bool:
        """Check whether a discovered host is covered by this target's scope.

        A candidate is in scope if it exactly matches a scope entry, or is
        a subdomain of a scope entry (e.g. 'api.example.com' is in scope
        for 'example.com'), or falls inside an authorized CIDR range.
        """
        candidate_host = candidate_host.rstrip(".").lower()

        for entry in self.scope:
            entry = entry.rstrip(".").lower()

            # CIDR range
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if _is_valid_ip(candidate_host) and ipaddress.ip_address(candidate_host) in network:
                        return True
                except ValueError:
                    continue
                continue

            # Exact match or subdomain match
            if candidate_host == entry or candidate_host.endswith("." + entry):
                return True

        return False

    def __str__(self) -> str:
        return self.base_url
