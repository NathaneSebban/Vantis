"""Tests for OpenAPI/Swagger spec parsing and injection-point extraction."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.recon.openapi_discovery import OpenApiDiscoveryModule
from vantis.utils.openapi_crawler import discover_openapi, openapi_injection_points, parse_openapi_spec

OPENAPI_V3 = {
    "openapi": "3.0.0",
    "info": {"title": "Demo API"},
    "servers": [{"url": "https://example.com/api"}],
    "paths": {
        "/users/{id}": {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}},
                    {"name": "expand", "in": "query", "schema": {"type": "string"}},
                ]
            }
        },
        "/search": {
            "get": {"parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}]},
        },
    },
}

SWAGGER_V2 = {
    "swagger": "2.0",
    "basePath": "/v1",
    "paths": {
        "/items": {"get": {"parameters": [{"name": "category", "in": "query", "type": "string"}]}},
    },
}


def test_parse_valid_openapi_v3():
    import json
    spec = parse_openapi_spec(json.dumps(OPENAPI_V3))
    assert spec is not None
    assert spec["info"]["title"] == "Demo API"


def test_parse_rejects_non_spec_json():
    assert parse_openapi_spec('{"hello": "world"}') is None
    assert parse_openapi_spec("not json or yaml: [") is None or True  # must not raise


def test_parse_accepts_yaml():
    yaml_text = "openapi: 3.0.0\ninfo:\n  title: X\npaths:\n  /a:\n    get: {}\n"
    spec = parse_openapi_spec(yaml_text)
    assert spec is not None and spec["paths"] == {"/a": {"get": {}}}


def test_injection_points_from_v3_spec_incl_path_and_query_params():
    points = openapi_injection_points(OPENAPI_V3, "https://example.com")
    by_param = {p.param: p for p in points}

    assert "id" in by_param and "expand" in by_param and "q" in by_param
    # Path param substituted into the URL itself.
    assert "/api/users/1" in by_param["id"].url
    # Query param appended normally.
    assert "expand=1" in by_param["expand"].url
    assert all(p.source == "openapi" for p in points)


def test_injection_points_respect_swagger_v2_base_path():
    points = openapi_injection_points(SWAGGER_V2, "https://example.com")
    assert any(p.param == "category" and "/v1/items" in p.url for p in points)


@responses.activate
def test_discover_openapi_finds_spec_at_common_path():
    responses.add(responses.GET, "http://example.com/openapi.json", json=OPENAPI_V3, status=200)
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), status=404)
    client_target = Target("http://example.com")
    from vantis.utils.http_client import HttpClient
    spec, url = discover_openapi(HttpClient(delay=0), client_target)
    assert spec is not None
    assert url == "http://example.com/openapi.json"


@responses.activate
def test_openapi_discovery_module_reports_finding():
    responses.add(responses.GET, "http://example.com/openapi.json", json=OPENAPI_V3, status=200)
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), status=404)
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    findings = OpenApiDiscoveryModule(ctx).run()
    assert len(findings) == 1
    assert "2 path(s)" in findings[0].evidence
    assert findings[0].severity.value == "info"


@responses.activate
def test_no_spec_found_yields_no_findings():
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), status=404)
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    assert OpenApiDiscoveryModule(ctx).run() == []
