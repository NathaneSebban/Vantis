from vantis.modules.cve.template_engine import Template


def test_template_from_dict():
    data = {
        "id": "test-template",
        "info": {"name": "Test", "severity": "high", "description": "desc"},
        "request": {"method": "GET", "path": "/foo"},
        "matchers": {"status": [200], "body_contains": ["marker"]},
    }
    t = Template.from_dict(data)
    assert t.id == "test-template"
    assert t.path == "/foo"
    assert t.matches(200, "some marker here", {})
    assert not t.matches(404, "some marker here", {})
    assert not t.matches(200, "no match here", {})


def test_template_header_matcher():
    data = {
        "id": "header-test",
        "info": {"name": "Header Test", "severity": "low"},
        "request": {"path": "/"},
        "matchers": {"header": {"Server": "nginx"}},
    }
    t = Template.from_dict(data)
    assert t.matches(200, "", {"Server": "nginx/1.18.0"})
    assert not t.matches(200, "", {"Server": "Apache"})


def test_template_without_matchers_never_matches():
    data = {
        "id": "no-matchers",
        "info": {"name": "No matchers", "severity": "info"},
        "request": {"path": "/"},
        "matchers": {},
    }
    t = Template.from_dict(data)
    assert not t.matches(200, "anything", {})


# -- run_templates: catch-all suppression + real match --------------------

import re
from pathlib import Path

import responses

from vantis.modules.cve.template_engine import load_templates, run_templates
from vantis.utils.http_client import HttpClient

_REAL_TMPL = Template.from_dict({
    "id": "real-marker", "info": {"name": "Real marker", "severity": "high"},
    "request": {"method": "GET", "path": "/secret"},
    "matchers": {"status": [200], "body_contains": ["TOPSECRET"]},
})
_HOME_TMPL = Template.from_dict({
    "id": "home-marker", "info": {"name": "Homepage marker", "severity": "high"},
    "request": {"method": "GET", "path": "/anything"},
    "matchers": {"status": [200], "body_contains": ["WELCOME"]},
})


@responses.activate
def test_run_templates_suppresses_catch_all_matches():
    # Catch-all server: every URL returns the same homepage containing WELCOME.
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"),
                  body="<html>WELCOME home</html>", status=200, content_type="text/html")
    findings = run_templates("http://example.com", [_REAL_TMPL, _HOME_TMPL], HttpClient(delay=0))
    # home-marker matches the catch-all baseline too -> suppressed; real-marker
    # never matches (no TOPSECRET anywhere) -> no findings at all.
    assert findings == []


@responses.activate
def test_run_templates_reports_genuine_match():
    def cb(request):
        if request.url.endswith("/secret"):
            return (200, {"Content-Type": "text/html"}, "<html>TOPSECRET data</html>")
        return (404, {}, "not found")  # proper 404 -> not catch-all
    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = run_templates("http://example.com", [_REAL_TMPL], HttpClient(delay=0))
    assert len(findings) == 1 and findings[0].title == "Real marker"


def test_all_shipped_templates_load():
    tdir = Path(__file__).resolve().parents[1] / "templates" / "cve"
    templates = load_templates(tdir)
    # Every YAML parsed into a Template with an id and at least one matcher.
    assert len(templates) >= 20
    for t in templates:
        assert t.id
        assert t.matcher_status or t.matcher_body_contains or t.matcher_header
