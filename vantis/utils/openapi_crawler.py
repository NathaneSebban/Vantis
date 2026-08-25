"""
OpenAPI/Swagger spec discovery and endpoint extraction.

Modern apps are API-first: instead of guessing parameters by crawling HTML,
reading the app's own OpenAPI/Swagger spec (when exposed, as it very often is
in dev/staging and even some production deployments) gives exact, complete
knowledge of every endpoint, method and parameter. This is the single biggest
lever for testing coverage on an API-backed app.

Detection only: fetches and parses the spec document; never calls the
documented endpoints itself (that's left to the modules that consume the
resulting injection points, which apply their own non-destructive rules).
"""
from __future__ import annotations

import json
from urllib.parse import urljoin, urlparse

import yaml

from vantis.utils.crawler import InjectionPoint, set_param

# Common locations apps expose their spec at.
COMMON_PATHS = [
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml",
    "v2/api-docs", "v3/api-docs",
    "api-docs", "api-docs.json",
    "api/openapi.json", "api/swagger.json",
    ".well-known/openapi.json",
]


def parse_openapi_spec(text: str) -> dict | None:
    """Parse a spec document (JSON or YAML, OpenAPI 3.x or Swagger 2.0).
    Returns None if it doesn't look like an OpenAPI/Swagger document. Pure and
    side-effect free — this is the unit-tested core."""
    try:
        data = json.loads(text)
    except ValueError:
        try:
            data = yaml.safe_load(text)
        except Exception:
            return None
    if not isinstance(data, dict):
        return None
    if "openapi" not in data and "swagger" not in data:
        return None
    if "paths" not in data or not isinstance(data["paths"], dict):
        return None
    return data


_METHODS = {"get", "post", "put", "delete", "patch", "head", "options"}


def openapi_injection_points(spec: dict, base_url: str) -> list[InjectionPoint]:
    """Extract one InjectionPoint per (endpoint, parameter) pair described by
    the spec: query parameters directly, and path parameters by substituting a
    literal placeholder so the URL is well-formed and testable. Pure function,
    unit-tested independent of any network access."""
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    # Resolve the API's base path: OpenAPI 3 'servers', Swagger 2 'basePath'.
    prefix = ""
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        prefix = urlparse(servers[0].get("url", "")).path or ""
    elif isinstance(spec.get("basePath"), str):
        prefix = spec["basePath"]

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        # Path-level parameters apply to every method under this path.
        shared_params = path_item.get("parameters", []) if isinstance(path_item.get("parameters"), list) else []

        resolved_path = path
        for m in _METHODS:
            operation = path_item.get(m)
            if not isinstance(operation, dict):
                continue
            op_params = operation.get("parameters", []) if isinstance(operation.get("parameters"), list) else []
            full_path = (prefix.rstrip("/") + path) if prefix else path
            url = urljoin(base_url.rstrip("/") + "/", full_path.lstrip("/"))

            # Substitute path params ({id} -> 1) so the resulting URL resolves
            # to a real (or at least well-formed) resource.
            test_url = url
            for param in [*shared_params, *op_params]:
                if not isinstance(param, dict):
                    continue
                name = param.get("name")
                if not name:
                    continue
                if param.get("in") == "path":
                    test_url = test_url.replace("{" + name + "}", "1")

            for param in [*shared_params, *op_params]:
                if not isinstance(param, dict):
                    continue
                name = param.get("name")
                loc = param.get("in")
                if not name or loc not in ("query", "path"):
                    continue
                key = (test_url, name)
                if key in seen:
                    continue
                seen.add(key)
                if loc == "query":
                    points.append(InjectionPoint(url=set_param(test_url, name, "1"), param=name, source="openapi"))
                else:  # path param: the substituted URL itself is the point
                    points.append(InjectionPoint(url=test_url, param=name, source="openapi"))

    return points


def discover_openapi(client, target, log=None) -> tuple[dict | None, str | None]:
    """Probe common spec locations. Returns (spec, url) or (None, None)."""
    log = log or (lambda _m: None)
    base = target.base_url
    for path in COMMON_PATHS:
        url = f"{base}/{path}"
        resp = client.get(url)
        if resp is None or resp.status_code != 200 or not resp.text:
            continue
        spec = parse_openapi_spec(resp.text)
        if spec is not None:
            log(f"OpenAPI/Swagger spec found at {url}")
            return spec, url
    return None, None
