"""Tests for cross-finding correlation."""
from vantis.core.correlator import correlate, correlate_report
from vantis.core.report import Finding, Report, Severity


def _f(module, title, target="https://example.com"):
    return Finding(module=module, title=title, severity=Severity.MEDIUM, target=target)


def test_no_correlation_when_findings_are_unrelated():
    findings = [_f("headers-check", "Missing CSP"), _f("tls-audit", "Weak cipher")]
    assert correlate(findings) == []


def test_credentials_plus_login_correlation_fires():
    findings = [
        _f("exposed-paths", "Exposed sensitive path: /.env"),
        _f("openapi-discovery", "OpenAPI spec discovered"),
    ]
    extra = correlate(findings)
    assert len(extra) == 1
    assert extra[0].severity == Severity.CRITICAL
    assert "credentials" in extra[0].title.lower()


def test_sqli_plus_admin_surface_correlation_fires():
    findings = [
        _f("sqli-check", "SQL injection in ?id="),
        _f("exposed-paths", "Exposed sensitive path: /actuator/env"),
    ]
    extra = correlate(findings)
    assert any("SQL injection" in f.title for f in extra)


def test_takeover_plus_secrets_correlation_fires():
    findings = [
        _f("subdomain-takeover", "Subdomain takeover: old.example.com"),
        _f("js-secrets", "Hardcoded API key in script.js"),
    ]
    extra = correlate(findings)
    assert any("takeover" in f.title.lower() for f in extra)


def test_correlate_report_adds_findings_to_the_report():
    report = Report(target="https://example.com")
    report.add(_f("sqli-check", "SQL injection in ?id="))
    report.add(_f("exposed-paths", "Exposed sensitive path: /server-status"))
    added = correlate_report(report)
    assert len(added) == 1
    assert added[0] in report.findings


def test_a_broken_rule_never_raises(monkeypatch):
    import vantis.core.correlator as correlator_mod

    def boom(_findings):
        raise RuntimeError("boom")

    monkeypatch.setattr(correlator_mod, "_RULES", [boom])
    assert correlate([_f("sqli-check", "x")]) == []
