"""Tests for the exposed-paths module's catch-all (soft-404) handling.

Regression guard for the false-positive class where a server answers 200 with
the same page for every URL: the module must not report every probed path as
"exposed".
"""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web.exposed_paths import ExposedPathsModule

CATCH_ALL_PAGE = "<!doctype html><html><body>" + "x" * 6000 + "</body></html>"


def _module() -> ExposedPathsModule:
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    return ExposedPathsModule(ctx)


@responses.activate
def test_catch_all_server_yields_no_false_positives():
    # Every URL returns the same 200 HTML page (SPA / soft-404 with status 200).
    responses.add(
        responses.GET,
        re.compile(r"http://example\.com/.*"),
        body=CATCH_ALL_PAGE,
        status=200,
        content_type="text/html",
    )
    findings = _module().run()
    assert findings == [], f"expected no findings on a catch-all server, got {len(findings)}"


@responses.activate
def test_real_exposed_file_is_still_detected():
    # A genuinely exposed .env (distinct, small body) behind an otherwise
    # catch-all server must still be found.
    responses.add(
        responses.GET,
        "http://example.com/.env",
        body="DB_PASSWORD=s3cret\nAPI_KEY=abc123\n",
        status=200,
        content_type="text/plain",
    )
    responses.add(
        responses.GET,
        re.compile(r"http://example\.com/.*"),
        body=CATCH_ALL_PAGE,
        status=200,
        content_type="text/html",
    )
    findings = _module().run()
    titles = [f.title for f in findings]
    assert any("/.env" in t for t in titles), titles
    # And it should not have flagged the catch-all paths.
    assert not any("/backup.sql" in t for t in titles), titles
    # Evidence is populated so the finding can be audited.
    env_finding = next(f for f in findings if "/.env" in f.title)
    assert "HTTP 200" in env_finding.evidence and "bytes" in env_finding.evidence


@responses.activate
def test_proper_404_server_reports_normally():
    # A server that correctly 404s unknown paths: no catch-all, so a real 200
    # on a probed path is a genuine hit.
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), status=404)
    responses.add(responses.GET, "http://example.com/docker-compose.yml",
                  body="services:\n  web:\n    image: nginx\n", status=200, content_type="text/plain")
    # responses matches in registration order, so register the specific 200 first:
    responses.reset()
    responses.add(responses.GET, "http://example.com/docker-compose.yml",
                  body="services:\n  web:\n    image: nginx\n", status=200, content_type="text/plain")
    responses.add(responses.GET, re.compile(r"http://example\.com/.*"), status=404)
    findings = _module().run()
    assert any("/docker-compose.yml" in f.title for f in findings)
