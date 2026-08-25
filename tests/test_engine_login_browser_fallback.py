"""Engine's login cascade: when the fast HTML-form parser finds no form
(typical of a JS-rendered SPA login page), it falls back to driving a real
headless browser — end-to-end against a local server serving a fake SPA."""
import http.server
import threading

import pytest

from vantis.core.engine import Engine
from vantis.core.plugin_base import ScanModule
from vantis.core.target import Target
from vantis.utils.browser_crawler import browser_crawl_available

# Same shape as tests/test_browser_login.py's SPA fixture: no <form> exists
# until client-side JS renders it — exactly what defeats the raw-HTML parser.
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
      document.cookie = 'session=spa-cookie; path=/';
    });
  });
}, 80);
</script>
</body></html>"""


# A cookie-less SPA: the token lives only in localStorage, mirroring apps
# like cyberxtel that use a JWT access token instead of a session cookie.
SPA_JWT_HTML = b"""<!doctype html><html><body>
<form>
  <input type="email" name="email">
  <input type="password" name="password">
  <button type="submit">Log in</button>
</form>
<script>
  document.querySelector('form').addEventListener('submit', (e) => {
    e.preventDefault();
    localStorage.setItem('auth-storage', JSON.stringify({
      state: {accessToken: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ccccccccccccccccccccccc',
              isAuthenticated: true},
    }));
  });
</script>
</body></html>"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(SPA_JWT_HTML if self.path == "/jwt" else SPA_LOGIN_HTML)

    def do_POST(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture
def spa_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class _NoOpModule(ScanModule):
    name = "noop"
    category = "web"

    def run(self):
        return []


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_falls_back_to_browser_login_when_html_form_not_found(spa_server):
    eng = Engine(
        target=Target(spa_server), categories=["web"], max_workers=1,
        login_url=spa_server + "/", login_username="user@test.com", login_password="hunter2",
    )
    eng._modules = [_NoOpModule]
    report = eng.run()

    login_findings = [f for f in report.findings if f.module == "auth-login"]
    assert len(login_findings) == 1
    f = login_findings[0]
    assert "succeeded" in f.title.lower()
    assert "headless browser" in f.description.lower()

    # The obtained cookie is actually usable by modules afterwards.
    assert eng.ctx.auth_cookies == {"session": "spa-cookie"}


@pytest.mark.skipif(not browser_crawl_available(), reason="playwright not installed")
def test_falls_back_to_bearer_token_when_spa_uses_jwt_in_storage(spa_server):
    eng = Engine(
        target=Target(spa_server), categories=["web"], max_workers=1,
        login_url=spa_server + "/jwt", login_username="user@test.com", login_password="hunter2",
    )
    eng._modules = [_NoOpModule]
    report = eng.run()

    login_findings = [f for f in report.findings if f.module == "auth-login"]
    assert len(login_findings) == 1
    f = login_findings[0]
    assert "succeeded" in f.title.lower()
    assert "bearer" in f.description.lower()

    # The token is usable by modules afterwards, as a standard Authorization header.
    assert eng.ctx.auth_headers == {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ccccccccccccccccccccccc"
    }
