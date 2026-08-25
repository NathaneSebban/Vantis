"""Tests for GraphQL introspection detection."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web.graphql_check import GraphQlCheckModule, parse_introspection_response

INTROSPECTION_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {"name": "Query", "kind": "OBJECT"},
                {"name": "User", "kind": "OBJECT"},
                {"name": "Post", "kind": "OBJECT"},
                {"name": "__Type", "kind": "OBJECT"},  # built-in, must be filtered out
            ],
        }
    }
}


def test_parse_valid_introspection_response():
    summary = parse_introspection_response(INTROSPECTION_RESPONSE)
    assert summary is not None
    assert summary["query_type"] == "Query"
    assert summary["type_count"] == 3  # __Type excluded
    assert "User" in summary["type_names"]


def test_parse_rejects_non_introspection_json():
    assert parse_introspection_response({"data": {}}) is None
    assert parse_introspection_response({"errors": [{"message": "introspection disabled"}]}) is None
    assert parse_introspection_response({}) is None


@responses.activate
def test_module_detects_enabled_introspection():
    responses.add(responses.POST, "http://example.com/graphql", json=INTROSPECTION_RESPONSE, status=200)
    responses.add(responses.POST, re.compile(r"http://example\.com/.*"), status=404)
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    findings = GraphQlCheckModule(ctx).run()
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert "3 type(s)" in findings[0].evidence


@responses.activate
def test_module_finds_nothing_when_introspection_disabled():
    responses.add(responses.POST, re.compile(r"http://example\.com/.*"),
                  json={"errors": [{"message": "introspection disabled"}]}, status=200)
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    assert GraphQlCheckModule(ctx).run() == []


@responses.activate
def test_module_finds_nothing_when_no_graphql_endpoint():
    responses.add(responses.POST, re.compile(r"http://example\.com/.*"), status=404)
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    assert GraphQlCheckModule(ctx).run() == []
