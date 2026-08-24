"""Tests for the pure certificate-analysis core of the TLS audit module."""
from datetime import datetime, timezone

from vantis.core.report import Severity
from vantis.modules.recon.tls_audit import analyze_certificate

NOW = datetime(2025, 6, 1, tzinfo=timezone.utc)


def _cert(not_before="May  1 00:00:00 2025 GMT", not_after="Aug  1 00:00:00 2025 GMT",
          sans=(("DNS", "example.com"), ("DNS", "*.example.com")), self_signed=False):
    subject = ((("commonName", "example.com"),),)
    issuer = subject if self_signed else ((("commonName", "Some CA"),),)
    return {"notBefore": not_before, "notAfter": not_after, "subjectAltName": sans,
            "subject": subject, "issuer": issuer}


def _titles(issues):
    return {t for _s, t, _e in issues}


def test_valid_cert_has_no_issues():
    assert analyze_certificate(_cert(), "example.com", NOW) == []


def test_expired_cert_is_high():
    issues = analyze_certificate(_cert(not_after="Jan  1 00:00:00 2025 GMT"), "example.com", NOW)
    assert any(s == Severity.HIGH and "Expired" in t for s, t, _ in issues)


def test_not_yet_valid_cert_is_high():
    issues = analyze_certificate(_cert(not_before="Jan  1 00:00:00 2026 GMT",
                                       not_after="Jan  1 00:00:00 2027 GMT"), "example.com", NOW)
    assert any(s == Severity.HIGH and "not yet valid" in t for s, t, _ in issues)


def test_expiring_soon_is_medium():
    issues = analyze_certificate(_cert(not_after="Jun  10 00:00:00 2025 GMT"), "example.com", NOW)
    assert any(s == Severity.MEDIUM and "expires soon" in t for s, t, _ in issues)


def test_hostname_mismatch_is_high():
    issues = analyze_certificate(_cert(sans=(("DNS", "other.com"),)), "example.com", NOW)
    assert any(s == Severity.HIGH and "hostname mismatch" in t for s, t, _ in issues)


def test_wildcard_matches_one_label():
    # api.example.com matches *.example.com
    assert "TLS certificate hostname mismatch" not in _titles(
        analyze_certificate(_cert(sans=(("DNS", "*.example.com"),)), "api.example.com", NOW))
    # deep.api.example.com does NOT match *.example.com
    assert "TLS certificate hostname mismatch" in _titles(
        analyze_certificate(_cert(sans=(("DNS", "*.example.com"),)), "deep.api.example.com", NOW))


def test_self_signed_is_medium():
    issues = analyze_certificate(_cert(self_signed=True), "example.com", NOW)
    assert any(s == Severity.MEDIUM and "Self-signed" in t for s, t, _ in issues)
