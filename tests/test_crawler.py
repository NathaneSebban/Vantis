"""Tests for injection-point discovery (the light crawler)."""
import re

import responses

from vantis.core.target import Target
from vantis.utils.crawler import discover_injection_points, set_param
from vantis.utils.http_client import HttpClient

LANDING = """
<html><body>
  <a href="/search?q=test">search</a>
  <a href="/product?id=5&ref=home">product</a>
  <a href="https://evil.com/steal?token=x">offsite</a>
  <form action="/login" method="get">
    <input name="username"><input name="password" type="password">
  </form>
  <form action="/comment" method="post">
    <input name="body">
  </form>
</body></html>
"""


def _client() -> HttpClient:
    return HttpClient(timeout=5, delay=0)


@responses.activate
def test_discovers_link_and_get_form_params_in_scope():
    responses.add(responses.GET, "http://example.com/", body=LANDING, status=200, content_type="text/html")
    points = discover_injection_points(_client(), Target("http://example.com"), max_points=50)

    params = {(p.param, p.source) for p in points}
    # Link query params:
    assert ("q", "link") in params
    assert ("id", "link") in params
    assert ("ref", "link") in params
    # GET form fields:
    assert ("username", "form") in params
    assert ("password", "form") in params
    # POST form field must NOT be included (different request shape):
    assert not any(p.param == "body" for p in points)
    # Off-scope host must NOT be included (no SSRF / scope escape):
    assert not any(p.param == "token" for p in points)
    assert not any("evil.com" in p.url for p in points)


@responses.activate
def test_target_own_params_are_discovered():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), body="<html>no links</html>",
                  status=200, content_type="text/html")
    points = discover_injection_points(_client(), Target("http://example.com/item?sku=42"))
    assert any(p.param == "sku" and p.source == "target" for p in points)


@responses.activate
def test_no_points_when_nothing_to_find():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), body="<html>plain</html>",
                  status=200, content_type="text/html")
    assert discover_injection_points(_client(), Target("http://example.com")) == []


def test_set_param_preserves_other_params():
    url = set_param("http://example.com/p?a=1&b=2", "a", "INJECT")
    assert "b=2" in url
    assert "a=INJECT" in url


@responses.activate
def test_discovers_params_from_robots_and_sitemap():
    responses.add(responses.GET, "http://example.com/robots.txt",
                  body="User-agent: *\nDisallow: /admin?debug=1\nDisallow: /\n", status=200,
                  content_type="text/plain")
    responses.add(responses.GET, "http://example.com/sitemap.xml",
                  body="<urlset><url><loc>http://example.com/p?id=5</loc></url></urlset>", status=200,
                  content_type="application/xml")
    responses.add(responses.GET, "http://example.com/sitemap_index.xml", status=404)
    responses.add(responses.GET, "http://example.com", body="<html>home</html>", status=200,
                  content_type="text/html")
    points = discover_injection_points(_client(), Target("http://example.com"), use_wayback=False)
    params = {(p.param, p.source) for p in points}
    assert ("debug", "sitemap") in params   # from robots.txt Disallow path
    assert ("id", "sitemap") in params       # from sitemap.xml <loc>


@responses.activate
def test_discovers_params_from_wayback():
    responses.add(responses.GET, re.compile(r"https://web\.archive\.org/cdx/.*"),
                  json=[["original"], ["http://example.com/search?q=test"],
                        ["http://example.com/nofilter"]], status=200)
    responses.add(responses.GET, "http://example.com", body="<html>home</html>", status=200,
                  content_type="text/html")
    responses.add(responses.GET, re.compile(r"http://example\.com/(robots|sitemap).*"), status=404)
    points = discover_injection_points(_client(), Target("http://example.com"))
    assert any(p.param == "q" for p in points)
