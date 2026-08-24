"""
Secret detection in exposed JavaScript.

Fetches the same-origin scripts referenced by the landing page and scans them
for high-confidence secret patterns (cloud keys, tokens, private keys). Only
distinctive, low-false-positive patterns are used; generic "password" mentions
are deliberately excluded. Detection only: secrets are reported redacted.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# label -> (compiled regex, severity). Patterns are chosen to be specific enough
# that a match is almost certainly a real secret.
SECRET_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.HIGH),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), Severity.HIGH),
    ("Stripe secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), Severity.MEDIUM),
    ("Firebase database URL", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), Severity.LOW),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"), Severity.HIGH),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), Severity.HIGH),
]


def _redact(value: str) -> str:
    if len(value) <= 10:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]} (len {len(value)})"


def scan_text_for_secrets(text: str) -> list[tuple[str, str, Severity]]:
    """Pure scanner: returns (label, redacted_match, severity). Unit-tested."""
    out: list[tuple[str, str, Severity]] = []
    seen: set[tuple[str, str]] = set()
    for label, pattern, severity in SECRET_PATTERNS:
        for m in pattern.findall(text):
            match = m if isinstance(m, str) else m[0]
            key = (label, match)
            if key in seen:
                continue
            seen.add(key)
            out.append((label, _redact(match), severity))
    return out


class JsSecretsModule(ScanModule):
    name = "js-secrets"
    category = "web"
    description = "Scan same-origin JavaScript for exposed API keys/tokens/secrets"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        target = self.ctx.target

        landing = client.get(target.url)
        if landing is None or not landing.text:
            return []

        # Collect same-scope script URLs (dedupe, cap for politeness).
        scripts: list[str] = []
        for src in _SCRIPT_SRC_RE.findall(landing.text):
            url = urljoin(target.url, src)
            host = urlparse(url).hostname or ""
            if host and target.is_in_scope(host) and url not in scripts:
                scripts.append(url)

        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for url in scripts[:20]:
            resp = client.get(url)
            if resp is None or not resp.text:
                continue
            for label, redacted, severity in scan_text_for_secrets(resp.text):
                key = (label, redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    module=self.name,
                    title=f"Possible secret in JavaScript: {label}",
                    severity=severity, target=str(target), matched_at=url,
                    evidence=f"{label}: {redacted}",
                    description="A credential-looking value is present in client-side JavaScript, where it is "
                                "readable by anyone. Verify and rotate it if it is a real secret.",
                    remediation="Never ship secrets to the client; move them server-side and rotate any exposed key.",
                    references=["https://cwe.mitre.org/data/definitions/615.html"],
                ))
        return findings
