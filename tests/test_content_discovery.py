"""Tests for the content-discovery module (wordlist + soft-404 filtering)."""
import re
from urllib.parse import urlparse

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web.content_discovery import ContentDiscoveryModule


def _ctx():
    return ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)


@responses.activate
def test_catch_all_server_yields_no_discoveries():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"),
                  body="<html>" + "x" * 5000 + "</html>", status=200, content_type="text/html")
    assert ContentDiscoveryModule(_ctx()).run() == []


@responses.activate
def test_real_paths_are_discovered_and_admin_is_low():
    def cb(request):
        path = urlparse(request.url).path.lstrip("/")
        if path == "admin":
            return (200, {"Content-Type": "text/html"}, "<html>admin panel login</html>")
        if path == "backup":
            return (403, {}, "forbidden")
        # Everything else 404s (server has a proper 404, so no catch-all).
        return (404, {}, "not found")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = ContentDiscoveryModule(_ctx()).run()
    titles = {f.title: f.severity.value for f in findings}

    assert "Discovered path: /admin" in titles
    assert titles["Discovered path: /admin"] == "low"  # sensitive
    assert any("Access-restricted path exists: /backup" in t for t in titles)
