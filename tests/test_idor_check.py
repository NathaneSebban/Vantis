"""Tests for IDOR / broken access control detection."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.utils.crawler import InjectionPoint
from vantis.modules.web import idor_check
from vantis.modules.web.idor_check import IdorCheckModule, looks_like_resource_id


def test_looks_like_resource_id_matches_id_names_with_id_values():
    assert looks_like_resource_id("id", "42")
    assert looks_like_resource_id("user_id", "1001")
    assert looks_like_resource_id("account", "550e8400-e29b-41d4-a716-446655440000")


def test_looks_like_resource_id_rejects_non_id_names_or_values():
    assert not looks_like_resource_id("q", "42")           # not an id-ish name
    assert not looks_like_resource_id("id", "hello")        # not numeric/uuid
    assert not looks_like_resource_id("page", "2")           # not an id-ish name


def _ctx_with_secondary():
    return ModuleContext(
        target=Target("http://example.com"), rate_limit_delay=0,
        auth_headers={"X-Identity": "A"},
        secondary_auth_headers={"X-Identity": "B"},
    )


@responses.activate
def test_no_secondary_identity_skips_entirely(monkeypatch):
    monkeypatch.setattr(idor_check, "discover_injection_points",
                        lambda *a, **k: [InjectionPoint(url="http://example.com/order?order_id=100", param="order_id")])
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)  # no secondary
    assert IdorCheckModule(ctx).run() == []


@responses.activate
def test_idor_detected_when_b_reads_a_resource(monkeypatch):
    monkeypatch.setattr(idor_check, "discover_injection_points",
                        lambda *a, **k: [InjectionPoint(url="http://example.com/order?order_id=100", param="order_id")])

    def cb(request):
        identity = request.headers.get("X-Identity")
        order_id = re.search(r"order_id=(\S+)", request.url).group(1)
        if identity == "A":
            return (200, {}, "<html>Order #100 for Alice, total $42</html>")
        # Identity B: cleanly denied for a random id (its own baseline)...
        if order_id != "100":
            return (404, {}, "<html>Not Found</html>")
        # ...but the bug is it ALSO succeeds for A's real id.
        return (200, {}, "<html>Order #100 for Alice, total $42</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/order.*"), callback=cb)
    findings = IdorCheckModule(_ctx_with_secondary()).run()
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert "order_id" in findings[0].title


@responses.activate
def test_no_idor_when_b_is_properly_denied(monkeypatch):
    monkeypatch.setattr(idor_check, "discover_injection_points",
                        lambda *a, **k: [InjectionPoint(url="http://example.com/order?order_id=100", param="order_id")])

    def cb(request):
        identity = request.headers.get("X-Identity")
        if identity == "A":
            return (200, {}, "<html>Order #100 for Alice, total $42</html>")
        return (403, {}, "<html>Forbidden</html>")  # B properly denied, every time

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/order.*"), callback=cb)
    assert IdorCheckModule(_ctx_with_secondary()).run() == []
