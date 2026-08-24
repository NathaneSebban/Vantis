"""
TLS/SSL configuration audit.

Connects once to the target over TLS and reports:
- expired / not-yet-valid certificates,
- hostname mismatch,
- self-signed certificates,
- deprecated protocol versions (TLS 1.0 / 1.1) still accepted.

The certificate analysis is a pure function (`analyze_certificate`) so it can be
unit-tested without a live TLS handshake; the network gathering is a thin,
best-effort wrapper that degrades gracefully when a host is unreachable.

Detection only: it never exploits weak TLS, it just reports it.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

# certificate timestamps look like: 'Jun  1 12:00:00 2025 GMT'
_CERT_TIME_FMT = "%b %d %H:%M:%S %Y %Z"


def _parse_cert_time(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, _CERT_TIME_FMT).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _cert_hostnames(cert: dict) -> list[str]:
    names: list[str] = []
    for entry in cert.get("subjectAltName", ()):  # ('DNS', 'example.com')
        if entry[0].lower() == "dns":
            names.append(entry[1].lower())
    # Fall back to the CN if there were no SANs.
    if not names:
        for rdn in cert.get("subject", ()):
            for key, val in rdn:
                if key == "commonName":
                    names.append(val.lower())
    return names


def _host_matches(host: str, patterns: list[str]) -> bool:
    host = host.rstrip(".").lower()
    for pat in patterns:
        pat = pat.rstrip(".").lower()
        if pat.startswith("*."):
            # Wildcard matches exactly one left-most label.
            if host.split(".", 1)[-1] == pat[2:]:
                return True
        elif host == pat:
            return True
    return False


def analyze_certificate(cert: dict, host: str, now: datetime | None = None) -> list[tuple[Severity, str, str]]:
    """Analyze a getpeercert()-style dict. Returns (severity, title, evidence)
    tuples. Pure and side-effect free — this is the unit-tested core."""
    now = now or datetime.now(timezone.utc)
    issues: list[tuple[Severity, str, str]] = []

    not_after = _parse_cert_time(cert.get("notAfter", ""))
    not_before = _parse_cert_time(cert.get("notBefore", ""))

    if not_after and now > not_after:
        issues.append((Severity.HIGH, "Expired TLS certificate", f"notAfter={cert.get('notAfter')}"))
    elif not_after and (not_after - now).days <= 14:
        issues.append((Severity.MEDIUM, "TLS certificate expires soon",
                       f"notAfter={cert.get('notAfter')} ({(not_after - now).days}d left)"))
    if not_before and now < not_before:
        issues.append((Severity.HIGH, "TLS certificate not yet valid", f"notBefore={cert.get('notBefore')}"))

    names = _cert_hostnames(cert)
    if names and not _host_matches(host, names):
        issues.append((Severity.HIGH, "TLS certificate hostname mismatch",
                       f"host {host} not in cert names {', '.join(names[:5])}"))

    subject = cert.get("subject")
    issuer = cert.get("issuer")
    if subject and issuer and subject == issuer:
        issues.append((Severity.MEDIUM, "Self-signed TLS certificate", "subject == issuer"))

    return issues


# Deprecated protocol versions to probe for (best effort; the local OpenSSL
# build may refuse to speak them at all, in which case we simply can't tell).
_DEPRECATED = []
for _name in ("TLSv1", "TLSv1_1"):
    _ver = getattr(ssl.TLSVersion, _name, None)
    if _ver is not None:
        _DEPRECATED.append((_name.replace("_", "."), _ver))


class TlsAuditModule(ScanModule):
    name = "tls-audit"
    category = "recon"
    description = "Audit TLS certificate validity and deprecated protocol support"

    def _connect_host_port(self) -> tuple[str, int] | None:
        t = self.ctx.target
        if t.scheme != "https" and t.port not in (443,):
            # Only audit TLS when the target actually speaks it.
            if t.scheme == "http" and t.port is None:
                return None
        host = t.host
        port = t.port or (443 if t.scheme == "https" else 443)
        return host, port

    def _fetch_cert(self, host: str, port: int) -> tuple[dict | None, str | None]:
        ctx = ssl.create_default_context()
        # We want the cert even if validation fails (to report WHY it fails),
        # so disable verification for the fetch and analyze ourselves.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.ctx.http_timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    return ssock.getpeercert() or {}, ssock.version()
        except Exception as e:  # noqa: BLE001 - unreachable / not TLS
            self.log(f"TLS connection to {host}:{port} failed: {e}")
            return None, None

    def _probe_deprecated(self, host: str, port: int) -> list[str]:
        accepted: list[str] = []
        for label, version in _DEPRECATED:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                with socket.create_connection((host, port), timeout=self.ctx.http_timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host):
                        accepted.append(label)
            except Exception:  # noqa: BLE001 - protocol refused (good) or unsupported locally
                continue
        return accepted

    def run(self) -> list[Finding]:
        hp = self._connect_host_port()
        if hp is None:
            return []
        host, port = hp

        cert, negotiated = self._fetch_cert(host, port)
        if cert is None:
            return []

        findings: list[Finding] = []
        base = f"https://{host}" + (f":{port}" if port != 443 else "")

        for severity, title, evidence in analyze_certificate(cert, host):
            findings.append(Finding(
                module=self.name, title=title, severity=severity, target=base,
                evidence=evidence, matched_at=base,
                remediation="Renew/replace the certificate and ensure the hostname and chain are correct.",
            ))

        for proto in self._probe_deprecated(host, port):
            findings.append(Finding(
                module=self.name,
                title=f"Deprecated TLS protocol accepted: {proto}",
                severity=Severity.MEDIUM, target=base, matched_at=base,
                evidence=f"Server completed a {proto} handshake",
                description=f"{proto} is deprecated and considered insecure.",
                remediation="Disable TLS 1.0/1.1 at the server/reverse proxy; require TLS 1.2+.",
                references=["https://datatracker.ietf.org/doc/rfc8996/"],
            ))

        if negotiated:
            findings.append(Finding(
                module=self.name, title="TLS endpoint fingerprinted", severity=Severity.INFO,
                target=base, evidence=f"Negotiated {negotiated}", matched_at=base,
            ))
        return findings
