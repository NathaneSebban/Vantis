"""
Cross-finding correlation.

A single finding is one data point; two findings together can mean the risk
is much higher than either alone (e.g. exposed .env credentials PLUS a login
form Vantis could reach with them is a much bigger deal than either fact in
isolation). This module looks at a completed scan's findings and raises a
small number of well-defined "combined risk" notes when specific patterns of
co-occurring findings are present.

Pure and read-only: it only reads a Report's findings and returns additional
Finding objects to add to it. It never makes network requests itself.
"""
from __future__ import annotations

from vantis.core.report import Confidence, Finding, Report, Severity

# Each rule: (title, description, severity, matcher)
# matcher(findings) -> list[Finding] whose presence together triggers it,
# or None if the pattern isn't present.


def _find(findings: list[Finding], *, module: str | None = None, title_contains: str | None = None) -> list[Finding]:
    out = []
    for f in findings:
        if module and f.module != module:
            continue
        if title_contains and title_contains.lower() not in f.title.lower():
            continue
        out.append(f)
    return out


def _rule_credentials_plus_login(findings: list[Finding]) -> Finding | None:
    """Exposed secrets/credentials (a .env file, a leaked JS secret) AND a
    reachable login form on the same target: an attacker doesn't just have
    leaked credentials, they have somewhere to use them immediately."""
    creds = (
        _find(findings, module="exposed-paths", title_contains=".env")
        + _find(findings, module="js-secrets")
    )
    login_related = _find(findings, title_contains="login") + _find(findings, module="openapi-discovery")
    if not creds:
        return None
    # A login surface is any auth-adjacent finding, or simply the presence of
    # a web application at all (headers-check always runs on a live site) —
    # keep this conservative and only fire when we have real signal.
    if not login_related:
        return None
    return Finding(
        module="correlator", confidence=Confidence.MEDIUM, owasp="A07:2021", cwe="CWE-522",
        title="Leaked credentials combined with a reachable login surface",
        severity=Severity.CRITICAL,
        target=creds[0].target,
        description=(
            f"{len(creds)} credential-exposure finding(s) were found alongside a login/authentication "
            "surface on the same target. Leaked credentials are far more dangerous when there is an "
            "immediate place to use them — treat this combination as an active compromise risk, not "
            "two separate low-priority items."
        ),
        evidence="; ".join(f"{f.module}: {f.title}" for f in (creds + login_related)[:5]),
        remediation="Rotate the exposed credentials immediately, then fix the exposure itself "
                    "(see the individual findings) before anything else.",
    )


def _rule_sqli_plus_exposed_admin(findings: list[Finding]) -> Finding | None:
    """A confirmed SQL injection point AND an exposed admin/debug panel:
    the injection may reach further than a single form suggests, and an
    exposed admin surface gives an attacker a much easier place to pivot
    from a successful injection (e.g. dumping session/admin tables)."""
    sqli = _find(findings, module="sqli-check")
    admin = (
        _find(findings, title_contains="actuator")
        + _find(findings, title_contains="server-status")
        + _find(findings, title_contains="phpinfo")
    )
    if not sqli or not admin:
        return None
    return Finding(
        module="correlator", confidence=Confidence.MEDIUM, owasp="A03:2021", cwe="CWE-89",
        title="SQL injection combined with an exposed admin/debug surface",
        severity=Severity.CRITICAL,
        target=sqli[0].target,
        description=(
            "A SQL injection point and an exposed administrative/debug endpoint were both found on this "
            "target. Together they widen the blast radius of the injection: attacker-controlled query "
            "results can be cross-referenced with configuration/debug details leaked by the admin surface."
        ),
        evidence="; ".join(f"{f.module}: {f.title}" for f in (sqli + admin)[:5]),
        remediation="Fix the SQL injection (parameterized queries) and remove or authenticate the "
                    "admin/debug endpoint — either alone reduces risk, but both together closes this path.",
    )


def _rule_takeover_plus_secrets(findings: list[Finding]) -> Finding | None:
    """A subdomain vulnerable to takeover AND leaked secrets: an attacker who
    takes over the subdomain can host content trusted by users of the main
    domain (cookies, CORS-allowed origins) and combine it with any leaked
    keys/tokens for that broader trust relationship."""
    takeover = _find(findings, module="subdomain-takeover")
    secrets_found = _find(findings, module="js-secrets")
    if not takeover or not secrets_found:
        return None
    return Finding(
        module="correlator", confidence=Confidence.MEDIUM, owasp="A05:2021", cwe="CWE-350",
        title="Subdomain takeover combined with leaked application secrets",
        severity=Severity.HIGH,
        target=takeover[0].target,
        description=(
            "A takeoverable subdomain and leaked secrets (API keys/tokens) were both found for this "
            "target. A subdomain under attacker control inherits the trust (cookies, CORS allow-lists) "
            "of the parent domain, which combined with leaked credentials materially increases impact."
        ),
        evidence="; ".join(f"{f.module}: {f.title}" for f in (takeover + secrets_found)[:5]),
        remediation="Remove the dangling DNS record (or reclaim the resource) and rotate the leaked "
                    "secrets — do both, not just one.",
    )


_RULES = [_rule_credentials_plus_login, _rule_sqli_plus_exposed_admin, _rule_takeover_plus_secrets]


def correlate(findings: list[Finding]) -> list[Finding]:
    """Run every correlation rule against a finished set of findings and
    return the additional 'combined risk' findings it produces (possibly
    empty). Never raises — a broken rule is skipped, not fatal."""
    extra: list[Finding] = []
    for rule in _RULES:
        try:
            result = rule(findings)
        except Exception:  # noqa: BLE001 - a correlation rule must never break a scan
            continue
        if result is not None:
            extra.append(result)
    return extra


def correlate_report(report: Report) -> list[Finding]:
    """Convenience wrapper: correlate a Report's own findings, add the
    results to it, and return what was added."""
    extra = correlate(report.findings)
    for f in extra:
        report.add(f)
    return extra
