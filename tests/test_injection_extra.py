"""Tests for path-traversal/LFI and SSTI detection modules."""
import re
from urllib.parse import parse_qs, urlparse

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web import path_traversal, ssti_check
from vantis.modules.web.path_traversal import PathTraversalModule
from vantis.modules.web.ssti_check import PRODUCT, SstiCheckModule


def _ctx():
    return ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)


# -- Path traversal ---------------------------------------------------

@responses.activate
def test_path_traversal_detected(monkeypatch):
    monkeypatch.setattr(path_traversal, "DEFAULT_PARAMS", ["file"])

    def cb(request):
        v = parse_qs(urlparse(request.url).query).get("file", [""])[0]
        if "etc/passwd" in v or "etc%2fpasswd" in v.lower():
            return (200, {}, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
        return (200, {}, "<html>normal page</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = PathTraversalModule(_ctx()).run()
    assert any(f.severity.value == "high" and "traversal" in f.title.lower() for f in findings)


@responses.activate
def test_no_traversal_when_marker_absent(monkeypatch):
    monkeypatch.setattr(path_traversal, "DEFAULT_PARAMS", ["file"])
    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"),
                           callback=lambda r: (200, {}, "<html>nothing here</html>"))
    assert PathTraversalModule(_ctx()).run() == []


# -- SSTI -------------------------------------------------------------

@responses.activate
def test_ssti_detected_on_evaluation(monkeypatch):
    monkeypatch.setattr(ssti_check, "DEFAULT_PARAMS", ["q"])

    def cb(request):
        v = parse_qs(urlparse(request.url).query).get("q", [""])[0]
        # Template engine evaluates the arithmetic -> product appears.
        if "1337*1338" in v and ("{{" in v or "${" in v or "#{" in v):
            return (200, {}, f"<html>Result: {PRODUCT}</html>")
        return (200, {}, "<html>Result: (nothing)</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = SstiCheckModule(_ctx()).run()
    assert any("template injection" in f.title.lower() for f in findings)


@responses.activate
def test_no_ssti_when_payload_only_reflected(monkeypatch):
    monkeypatch.setattr(ssti_check, "DEFAULT_PARAMS", ["q"])

    def cb(request):
        v = parse_qs(urlparse(request.url).query).get("q", [""])[0]
        # Reflected literally, NOT evaluated -> product never appears.
        return (200, {}, f"<html>You searched: {v}</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    assert SstiCheckModule(_ctx()).run() == []
