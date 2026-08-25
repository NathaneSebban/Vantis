"""
GraphQL endpoint discovery and introspection audit.

GraphQL introspection is a standard, built-in query that (when enabled) lets
anyone ask the API "what can you do?" and get back the complete schema: every
type, query, mutation and field. It's invaluable for testing (maps the whole
API in one request) but is itself a finding — introspection is widely
recommended to be disabled in production, since it hands an attacker the same
complete map.

Detection only: sends the standard read-only introspection query, nothing
else. Never issues a mutation or any query beyond introspection.
"""
from __future__ import annotations

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity

COMMON_PATHS = ["graphql", "api/graphql", "graphql/console", "v1/graphql", "query"]

# The standard introspection query (read-only, defined by the GraphQL spec).
INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { name kind }
  }
}
"""


def parse_introspection_response(data: dict) -> dict | None:
    """Pure parser: given a decoded JSON response body, return a summary dict
    if it's a valid introspection result, else None. Unit-tested independent
    of any network access."""
    schema = (data or {}).get("data", {}).get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict) or "types" not in schema:
        return None
    types = [t for t in schema.get("types", []) if isinstance(t, dict) and t.get("name")]
    # Filter out the built-in introspection/scalar types to count real ones.
    user_types = [t for t in types if not str(t.get("name", "")).startswith("__")]
    return {
        "query_type": (schema.get("queryType") or {}).get("name"),
        "mutation_type": (schema.get("mutationType") or {}).get("name"),
        "type_count": len(user_types),
        "type_names": [t["name"] for t in user_types[:15]],
    }


class GraphQlCheckModule(ScanModule):
    name = "graphql-introspection"
    category = "web"
    description = "Detect GraphQL endpoints and check whether introspection is enabled"

    def run(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        base = str(self.ctx.target).rstrip("/")
        findings: list[Finding] = []

        for path in COMMON_PATHS:
            url = f"{base}/{path}"
            resp = client.post(url, json={"query": INTROSPECTION_QUERY})
            if resp is None or resp.status_code != 200:
                continue
            try:
                data = resp.json()
            except ValueError:
                continue

            summary = parse_introspection_response(data)
            if summary is None:
                continue

            findings.append(Finding(
                module=self.name,
                title="GraphQL introspection is enabled",
                severity=Severity.MEDIUM,
                target=str(self.ctx.target),
                matched_at=url,
                evidence=f"{summary['type_count']} type(s) exposed, e.g. {', '.join(summary['type_names'][:6])}",
                description="The GraphQL endpoint answers the standard introspection query, exposing the "
                            "full schema (every type, query and mutation). This maps the entire API surface "
                            "for anyone who finds the endpoint.",
                remediation="Disable introspection in production (most GraphQL server libraries offer a "
                            "single config flag for this) or gate it behind authentication.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"],
            ))
            break  # one confirmed GraphQL endpoint is enough signal

        return findings
