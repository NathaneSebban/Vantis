"""
Lightweight TCP connect-scan over a curated list of common ports.

Deliberately NOT a full 1-65535 stealth/SYN scanner (that needs raw
sockets / root and starts crossing into "aggressive" territory better
left to nmap). This does a polite, threaded TCP-connect scan of the
ports that actually matter for recon: web, admin panels, databases,
common misconfig targets.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP-submission", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 2375: "Docker (unencrypted!)",
    2376: "Docker TLS", 27017: "MongoDB", 3000: "Dev-server", 3306: "MySQL",
    3389: "RDP", 5000: "Dev-server", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 8000: "HTTP-alt",
    8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "HTTP-alt",
    9000: "PHP-FPM/misc", 9200: "Elasticsearch", 9300: "Elasticsearch-transport",
    11211: "Memcached", 27018: "MongoDB",
}

# Ports that, if open and unauthenticated, are almost always a real problem
SENSITIVE_PORTS = {2375, 6379, 9200, 27017, 5984, 11211, 5432, 3306, 1433, 5900}


class PortScanModule(ScanModule):
    name = "port-scan"
    category = "recon"
    description = "TCP connect scan over common/high-value ports"

    def _check_port(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return True
        except (OSError, socket.timeout):
            return False

    def run(self) -> list[Finding]:
        hosts = [self.ctx.target.host] + (self.ctx.extra_hosts or [])
        hosts = list(dict.fromkeys(hosts))[:25]  # cap to avoid runaway scans

        findings: list[Finding] = []

        for host in hosts:
            open_ports: list[int] = []
            with ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(self._check_port, host, p): p for p in COMMON_PORTS}
                for fut in as_completed(futures):
                    port = futures[fut]
                    if fut.result():
                        open_ports.append(port)

            if not open_ports:
                continue

            service_list = ", ".join(f"{p}/{COMMON_PORTS[p]}" for p in sorted(open_ports))
            findings.append(
                Finding(
                    module=self.name,
                    title=f"{len(open_ports)} open port(s) on {host}",
                    severity=Severity.INFO,
                    target=host,
                    evidence=service_list,
                )
            )

            for port in open_ports:
                if port in SENSITIVE_PORTS:
                    findings.append(
                        Finding(
                            module=self.name,
                            title=f"Sensitive service exposed: {COMMON_PORTS[port]} on port {port}",
                            severity=Severity.MEDIUM,
                            target=host,
                            matched_at=f"{host}:{port}",
                            description=(
                                f"{COMMON_PORTS[port]} is reachable from outside. If this is "
                                "unauthenticated or unnecessary on a public interface, it's a "
                                "common source of real-world breaches (exposed databases/caches)."
                            ),
                            remediation="Restrict to internal network/VPN, enable auth, or firewall the port.",
                        )
                    )

        return findings
