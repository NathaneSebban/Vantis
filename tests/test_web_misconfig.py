"""Tests for the quick web-misconfig modules: CORS, open redirect, HTTP methods."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web.cors_check import CorsCheckModule, PROBE_ORIGIN
from vantis.modules.web.open_redirect import CANARY_HOST, CANARY_URL, OpenRedirectModule
from vantis.modules.web.http_methods import HttpMethodsModule


def _ctx(url="http://example.com"):
    return ModuleContext(target=Target(url), rate_limit_delay=0)


# -- CORS -------------------------------------------------------------

@responses.activate
def test_cors_reflected_origin_with_credentials_is_high():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), body="ok", status=200,
                  headers={"Access-Control-Allow-Origin": PROBE_ORIGIN,
                           "Access-Control-Allow-Credentials": "true"})
    findings = CorsCheckModule(_ctx()).run()
    assert any(f.severity.value == "high" and "credentials" in f.title for f in findings)


@responses.activate
def test_cors_reflected_without_credentials_is_medium():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), body="ok", status=200,
                  headers={"Access-Control-Allow-Origin": PROBE_ORIGIN})
    findings = CorsCheckModule(_ctx()).run()
    assert findings and all(f.severity.value == "medium" for f in findings)


@responses.activate
def test_cors_properly_restricted_is_clean():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), body="ok", status=200,
                  headers={"Access-Control-Allow-Origin": "https://trusted.example"})
    assert CorsCheckModule(_ctx()).run() == []


# -- Open redirect ----------------------------------------------------

@responses.activate
def test_open_redirect_detected():
    # Landing page (crawler) has no links; server 302s the redirect param off-site.
    responses.add(responses.GET, "http://example.com/", body="<html>home</html>", status=200,
                  content_type="text/html")
    responses.add(responses.GET, re.compile(r"http://example\.com/.*redirect=.*"),
                  status=302, headers={"Location": CANARY_URL})
    findings = OpenRedirectModule(_ctx()).run()
    assert any("Open redirect" in f.title for f in findings)


@responses.activate
def test_no_open_redirect_when_location_is_local():
    responses.add(responses.GET, "http://example.com/", body="<html>home</html>", status=200,
                  content_type="text/html")
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"),
                  status=302, headers={"Location": "/dashboard"})
    assert OpenRedirectModule(_ctx()).run() == []


# -- HTTP methods -----------------------------------------------------

@responses.activate
def test_dangerous_methods_flagged():
    responses.add(responses.OPTIONS, "http://example.com", status=200,
                  headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})
    findings = HttpMethodsModule(_ctx()).run()
    assert any("PUT" in f.title and "DELETE" in f.title for f in findings)


@responses.activate
def test_safe_methods_are_clean():
    responses.add(responses.OPTIONS, "http://example.com", status=200,
                  headers={"Allow": "GET, HEAD, POST, OPTIONS"})
    # No TRACE registered -> request returns nothing special.
    findings = HttpMethodsModule(_ctx()).run()
    assert findings == []
