"""Tests for the headless-browser crawler (Playwright).

The heavy browser-driving path is exercised end-to-end against a tiny local
HTTP server serving a JS-rendered page (real Chromium, real network capture) —
this is the part a fake/mock can't meaningfully verify. Availability/graceful-
degradation is tested independently of whether Playwright is installed.
"""
import http.server
import threading

import pytest

from vantis.core.target import Target
from vantis.utils.browser_crawler import browser_crawl, browser_crawl_available

SPA_HTML = b"""<!doctype html><html><body>
<div id="app"></div>
<script>
  // Simulate an SPA: render a link client-side and fire an API call, neither
  // of which a static HTML crawler (no JS execution) could ever see.
  document.getElementById('app').innerHTML = '<a href="/rendered?token=abc">go</a>';
  fetch('/api/items?category=widgets');
</script>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(SPA_HTML if self.path == "/" else b"{}")

    def log_message(self, *args):
        pass  # keep test output quiet


@pytest.fixture
def local_spa_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_browser_crawl_available_reflects_playwright_install():
    # Whatever the environment, this must not raise, and must return a bool.
    assert isinstance(browser_crawl_available(), bool)


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_browser_crawl_finds_js_rendered_link_and_xhr_call(local_spa_server):
    target = Target(local_spa_server)
    points = browser_crawl(target, timeout_ms=10000)

    sources = {p.source for p in points}
    params = {p.param for p in points}

    # The rendered <a href> (client-side, invisible to a static crawler).
    assert "token" in params
    assert "browser-link" in sources
    # The fetch() call the page's JS makes on load.
    assert "category" in params
    assert "browser-xhr" in sources


def test_browser_crawl_returns_empty_when_unavailable(monkeypatch):
    import vantis.utils.browser_crawler as bc

    monkeypatch.setattr(bc, "browser_crawl_available", lambda: False)
    assert bc.browser_crawl(Target("http://example.com")) == []
