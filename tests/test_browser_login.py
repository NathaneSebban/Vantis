"""Tests for headless-browser login (Playwright) — the fallback for SPA login
forms that only exist in the DOM after client-side JS renders them, which
auth_login.perform_login() (raw HTML parsing) can never see.
"""
import http.server
import threading

import pytest

from vantis.utils.browser_crawler import browser_crawl_available, browser_login

# Simulates a React/Vue-style SPA: the initial HTML has no <form> at all —
# it's rendered client-side after a short delay, mirroring a real app that
# waits on an auth-config fetch or a lazy-loaded route before showing the
# login form. Submitting posts to an API and sets a session cookie via JS,
# mirroring what a real app does after its login API call succeeds.
SPA_LOGIN_HTML = b"""<!doctype html><html><body>
<div id="app"></div>
<script>
setTimeout(() => {
  document.getElementById('app').innerHTML =
    '<form id="f">' +
    '<input type="email" id="user" name="email">' +
    '<input type="password" id="pass" name="password">' +
    '<button type="submit">Log in</button>' +
    '</form>';
  document.getElementById('f').addEventListener('submit', (e) => {
    e.preventDefault();
    fetch('/api/login', {method: 'POST'}).then(() => {
      document.cookie = 'session=abc123; path=/';
    });
  });
}, 80);
</script>
</body></html>"""

# A form that renders immediately but where credentials are always rejected
# (no cookie is ever set) — used to verify the "wrong credentials" path.
SPA_REJECT_HTML = b"""<!doctype html><html><body>
<form>
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Log in</button>
</form>
<script>
  document.querySelector('form').addEventListener('submit', (e) => e.preventDefault());
</script>
</body></html>"""

# No password field ever appears — a page that isn't a login page at all.
NO_FORM_HTML = b"<!doctype html><html><body><div id='app'>Nothing here</div></body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = {
            "/": SPA_LOGIN_HTML,
            "/reject": SPA_REJECT_HTML,
            "/noform": NO_FORM_HTML,
        }.get(self.path, b"")
        self.wfile.write(body)

    def do_POST(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_browser_login_waits_for_spa_form_and_succeeds(local_server):
    cookies = browser_login(local_server + "/", "user@test.com", "hunter2", timeout_ms=10000)
    assert cookies == {"session": "abc123"}


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_browser_login_returns_none_when_no_cookie_changes(local_server):
    assert browser_login(local_server + "/reject", "user@test.com", "wrong", timeout_ms=10000) is None


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_browser_login_returns_none_when_no_form_ever_appears(local_server):
    assert browser_login(local_server + "/noform", "a", "b", timeout_ms=3000) is None


def test_browser_login_returns_none_when_playwright_unavailable(monkeypatch):
    import vantis.utils.browser_crawler as bc

    monkeypatch.setattr(bc, "browser_crawl_available", lambda: False)
    assert bc.browser_login("http://example.com/login", "a", "b") is None
