"""Authenticated scanning: auth headers/cookies must reach every request."""
import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web.headers_check import HeadersCheckModule
from vantis.utils.http_client import HttpClient


@responses.activate
def test_http_client_sends_auth_headers_and_cookies():
    responses.add(responses.GET, "http://example.com/", body="ok", status=200)
    client = HttpClient(delay=0, headers={"Authorization": "Bearer secret"}, cookies={"session": "abc123"})
    client.get("http://example.com/")

    sent = responses.calls[-1].request
    assert sent.headers["Authorization"] == "Bearer secret"
    assert "session=abc123" in sent.headers.get("Cookie", "")


@responses.activate
def test_context_factory_propagates_auth_to_modules():
    responses.add(responses.GET, "http://example.com", body="ok", status=200)
    ctx = ModuleContext(
        target=Target("http://example.com"),
        rate_limit_delay=0,
        auth_headers={"Authorization": "Bearer tok"},
        auth_cookies={"sid": "xyz"},
    )
    # A module built through the context must scan as the authenticated user.
    HeadersCheckModule(ctx).run()
    sent = responses.calls[-1].request
    assert sent.headers["Authorization"] == "Bearer tok"
    assert "sid=xyz" in sent.headers.get("Cookie", "")


def test_context_without_auth_builds_plain_client():
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    client = ctx.new_http_client()
    assert "Authorization" not in client.session.headers
