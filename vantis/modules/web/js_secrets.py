"""
Secret detection in exposed JavaScript.

Fetches the same-origin scripts referenced by the landing page and scans them
for two kinds of signal:
1. High-confidence, known secret formats (cloud keys, tokens, private keys) —
   distinctive, low-false-positive regex patterns.
2. Generic entropy-based detection: a variable named like a credential
   ("apiKey", "authToken"...) assigned a long, high-Shannon-entropy string.
   This is what catches INTERNAL/unknown-format secrets that no format
   pattern could ever match — the tradeoff is lower confidence, so these are
   flagged separately and at lower severity/confidence than a format match.

Detection only: secrets are reported redacted, never in full.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from urllib.parse import urljoin, urlparse

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Confidence, Finding, Severity

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


def shannon_entropy(s: str) -> float:
    """Bits of entropy per character. Pure math, unit-tested. Random-looking
    tokens (base64/hex secrets) score high (~4.5-6); English words, repeated
    characters, and sequential/placeholder strings score low."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


# variable-name hint -> assigned string literal, e.g.  apiKey: "xxxxxxxx...."
_ENTROPY_ASSIGNMENT_RE = re.compile(
    r"""(?i)\b(\w*(?:api[_-]?key|secret|token|auth|credential|passwd|access[_-]?key)\w*)\s*[:=]\s*["']([A-Za-z0-9+/_\-.]{20,100})["']"""
)
_PLACEHOLDER_RE = re.compile(r"(?i)your[_-]?|example|changeme|xxxx|0000|test|dummy|placeholder|sample")
_ENTROPY_THRESHOLD = 3.5  # bits/char; random base64/hex secrets comfortably clear this


def scan_text_for_entropy_secrets(text: str, known_values: set[str] | None = None) -> list[tuple[str, str]]:
    """Pure scanner: generic detection for credential-named variables assigned
    a high-entropy value, catching secrets no format pattern recognizes.
    Returns (variable_name, redacted_value) pairs. Skips values already caught
    by a known format pattern (`known_values`) to avoid double-reporting, and
    skips obvious placeholders. Unit-tested independent of any network call."""
    known_values = known_values or set()
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for var_name, value in _ENTROPY_ASSIGNMENT_RE.findall(text):
        if value in known_values or value in seen:
            continue
        if _PLACEHOLDER_RE.search(value):
            continue
        if shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        seen.add(value)
        out.append((var_name, _redact(value)))
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

            known_values: set[str] = set()
            for label, redacted, severity in scan_text_for_secrets(resp.text):
                key = (label, redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    module=self.name, confidence=Confidence.HIGH, owasp="A02:2021", cwe="CWE-798",
                    title=f"Possible secret in JavaScript: {label}",
                    severity=severity, target=str(target), matched_at=url,
                    evidence=f"{label}: {redacted}",
                    description="A credential-looking value is present in client-side JavaScript, where it is "
                                "readable by anyone. Verify and rotate it if it is a real secret.",
                    remediation="Never ship secrets to the client; move them server-side and rotate any exposed key.",
                    references=["https://cwe.mitre.org/data/definitions/615.html"],
                ))

            # Second pass: generic high-entropy detection for unknown formats
            # (e.g. internal API keys). Lower confidence — it's a statistical
            # heuristic, not a recognized format — so it's flagged separately.
            for var_name, redacted in scan_text_for_entropy_secrets(resp.text, known_values):
                key = ("entropy", redacted)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    module=self.name, confidence=Confidence.LOW, owasp="A02:2021", cwe="CWE-798",
                    title=f"Possible high-entropy secret in JavaScript: {var_name}",
                    severity=Severity.LOW, target=str(target), matched_at=url,
                    evidence=f"{var_name}: {redacted}",
                    description="A credential-named variable is assigned a long, random-looking value. This "
                                "doesn't match a known key format, so it may be a false positive (e.g. a hash "
                                "or generated id) — verify manually before reporting.",
                    remediation="Never ship secrets to the client; move them server-side and rotate any exposed key.",
                    references=["https://cwe.mitre.org/data/definitions/615.html"],
                ))
        return findings
