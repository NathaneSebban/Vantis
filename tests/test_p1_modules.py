"""Tests for P1 modules: subdomain takeover and JS secret detection."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.report import Severity
from vantis.core.target import Target
from vantis.modules.recon.subdomain_takeover import SubdomainTakeoverModule
from vantis.modules.web.js_secrets import JsSecretsModule, scan_text_for_secrets


# -- subdomain takeover ----------------------------------------------

@responses.activate
def test_takeover_fingerprint_detected():
    responses.add(responses.GET, "https://example.com/",
                  body="<html>There isn't a GitHub Pages site here.</html>", status=404)
    ctx = ModuleContext(target=Target("https://example.com"), rate_limit_delay=0)
    findings = SubdomainTakeoverModule(ctx).run()
    assert any(f.severity.value == "high" and "GitHub Pages" in f.title for f in findings)


@responses.activate
def test_no_takeover_on_normal_site():
    responses.add(responses.GET, re.compile(r"https://example\.com/.*"),
                  body="<html>Welcome to our site</html>", status=200)
    ctx = ModuleContext(target=Target("https://example.com"), rate_limit_delay=0)
    assert SubdomainTakeoverModule(ctx).run() == []


# -- JS secrets (pure scanner) ---------------------------------------

def test_scan_finds_aws_and_stripe_keys():
    text = 'const c={aws:"AKIAIOSFODNN7EXAMPLE", stripe:"sk_live_abcdef0123456789ABCDEFdummy"};'
    hits = {label: sev for label, _redacted, sev in scan_text_for_secrets(text)}
    assert "AWS access key id" in hits
    assert hits["Stripe secret key"] == Severity.CRITICAL


def test_scan_redacts_and_ignores_plain_text():
    assert scan_text_for_secrets("just some normal javascript; var x = 1;") == []
    # Google API key = "AIza" + exactly 35 chars.
    hits = scan_text_for_secrets("key=AIza" + "0" * 35)
    assert hits and hits[0][0] == "Google API key" and "…" in hits[0][1]  # redacted


# -- JS secrets (module, end to end) ---------------------------------

@responses.activate
def test_js_secrets_module_reads_linked_scripts():
    responses.add(responses.GET, "http://example.com",
                  body='<html><script src="/app.js"></script></html>', status=200,
                  content_type="text/html")
    responses.add(responses.GET, "http://example.com/app.js",
                  body='var apiKey="AKIAIOSFODNN7EXAMPLE";', status=200,
                  content_type="application/javascript")
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    findings = JsSecretsModule(ctx).run()
    assert any("AWS access key id" in f.title for f in findings)
    # Never leak the full secret in the finding.
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.evidence for f in findings)


# -- entropy-based secret detection ------------------------------------

from vantis.modules.web.js_secrets import scan_text_for_entropy_secrets, shannon_entropy


def test_shannon_entropy_random_string_scores_high():
    assert shannon_entropy("aB3xQ9zK7mP2vN8rL4wT6yU1") > 3.5


def test_shannon_entropy_repeated_chars_scores_low():
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaa") < 1.0


def test_shannon_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_scan_finds_credential_named_high_entropy_value():
    text = 'const cfg = {internalApiKey: "qX7mZ9pL2vR8kW4jT6yB1nH3fD5sC0aE"};'
    hits = scan_text_for_entropy_secrets(text)
    assert len(hits) == 1
    assert "internalApiKey" in hits[0][0]


def test_entropy_scan_skips_placeholders_and_low_entropy():
    text = 'const a = {apiKey: "YOUR_API_KEY_HERE_1234567890"};'
    assert scan_text_for_entropy_secrets(text) == []
    text2 = 'const b = {authToken: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"};'
    assert scan_text_for_entropy_secrets(text2) == []


def test_entropy_scan_skips_values_already_known():
    value = "qX7mZ9pL2vR8kW4jT6yB1nH3fD5sC0aE"
    text = f'const cfg = {{secretToken: "{value}"}};'
    assert scan_text_for_entropy_secrets(text, known_values={value}) == []


@responses.activate
def test_js_secrets_module_reports_entropy_finding_at_low_confidence():
    responses.add(responses.GET, "http://example.com",
                  body='<html><script src="/app.js"></script></html>', status=200,
                  content_type="text/html")
    responses.add(responses.GET, "http://example.com/app.js",
                  body='var internalToken = "qX7mZ9pL2vR8kW4jT6yB1nH3fD5sC0aE";',
                  status=200, content_type="application/javascript")
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    findings = JsSecretsModule(ctx).run()
    assert any(f.confidence.value == "low" and "entropy" in f.title.lower() for f in findings)
