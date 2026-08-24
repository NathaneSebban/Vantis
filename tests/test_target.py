import pytest

from vantis.core.target import Target


def test_basic_target_parsing():
    t = Target(raw="https://example.com/path?x=1")
    assert t.host == "example.com"
    assert t.scheme == "https"
    assert t.base_url == "https://example.com"


def test_target_preserves_path_and_query():
    t = Target(raw="https://example.com/search?q=hello&page=2")
    # str()/base_url stay the origin (for web-root-relative modules)...
    assert str(t) == "https://example.com"
    assert t.base_url == "https://example.com"
    # ...but the full URL, path and query are kept for parameter testing.
    assert t.path == "/search"
    assert t.query == "q=hello&page=2"
    assert t.url == "https://example.com/search?q=hello&page=2"


def test_bare_domain_full_url_is_origin():
    t = Target(raw="example.com")
    assert t.url == "http://example.com"
    assert t.path == ""
    assert t.query == ""


def test_bare_domain_defaults_to_http():
    t = Target(raw="example.com")
    assert t.scheme == "http"
    assert t.host == "example.com"


def test_scope_defaults_to_target_host():
    t = Target(raw="example.com")
    assert t.scope == ["example.com"]


def test_subdomain_is_in_scope():
    t = Target(raw="example.com")
    assert t.is_in_scope("api.example.com")
    assert t.is_in_scope("example.com")


def test_unrelated_domain_is_not_in_scope():
    t = Target(raw="example.com")
    assert not t.is_in_scope("evil.com")
    assert not t.is_in_scope("notexample.com")


def test_explicit_scope_list():
    t = Target(raw="example.com", scope=["example.com", "partner.org"])
    assert t.is_in_scope("staging.partner.org")
    assert not t.is_in_scope("partner.evil.com")


def test_cidr_scope():
    t = Target(raw="10.0.0.5", scope=["10.0.0.0/24"])
    assert t.is_in_scope("10.0.0.42")
    assert not t.is_in_scope("10.0.1.42")


def test_invalid_target_raises():
    with pytest.raises(ValueError):
        Target(raw="not a host!!")
