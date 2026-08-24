"""Tests for reflected-XSS detection, focused on the Content-Type guard."""
import html
import re
from urllib.parse import parse_qs, urlparse

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web import xss_check
from vantis.modules.web.xss_check import XssCheckModule


def _run(monkeypatch) -> list:
    monkeypatch.setattr(xss_check, "DEFAULT_PARAMS", ["q"])
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    return XssCheckModule(ctx).run()


def _reflected_value(request) -> str:
    return parse_qs(urlparse(request.url).query).get("q", [""])[0]


@responses.activate
def test_unescaped_reflection_in_html_is_high(monkeypatch):
    def cb(request):
        return (200, {"Content-Type": "text/html"}, f"<html>You searched: {_reflected_value(request)}</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert any(f.severity.value == "high" and "Reflected XSS" in f.title for f in findings)


@responses.activate
def test_unescaped_reflection_in_json_is_not_xss(monkeypatch):
    # Same raw reflection, but served as JSON -> NOT executable as XSS.
    def cb(request):
        return (200, {"Content-Type": "application/json"}, f'{{"q": "{_reflected_value(request)}"}}')

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert not any(f.severity.value == "high" for f in findings)
    assert any(f.severity.value == "info" and "non-HTML" in f.title for f in findings)


@responses.activate
def test_escaped_reflection_is_info(monkeypatch):
    def cb(request):
        return (200, {"Content-Type": "text/html"}, f"<html>{html.escape(_reflected_value(request))}</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert not any(f.severity.value == "high" for f in findings)
    assert any(f.severity.value == "info" and "encoded" in f.title for f in findings)
