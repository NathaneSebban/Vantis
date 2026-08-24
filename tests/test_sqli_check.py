"""Tests for non-destructive SQLi detection, focused on the baseline/noise
guards that suppress false positives."""
import re
from urllib.parse import parse_qs, urlparse

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.web import sqli_check
from vantis.modules.web.sqli_check import SqliCheckModule


def _run(monkeypatch) -> list:
    monkeypatch.setattr(sqli_check, "DEFAULT_PARAMS", ["id"])
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    return SqliCheckModule(ctx).run()


def _val(request) -> str:
    return parse_qs(urlparse(request.url).query).get("id", [""])[0]


@responses.activate
def test_error_based_flags_only_new_errors(monkeypatch):
    # Error appears ONLY when a quote is injected; benign baseline is clean.
    def cb(request):
        v = _val(request)
        if "'" in v:
            body = "<html>You have an error in your SQL syntax; near line 1</html>"
        else:
            body = "<html>normal product page</html>"
        return (200, {"Content-Type": "text/html"}, body)

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert any(f.severity.value == "high" and "SQL injection" in f.title for f in findings)


@responses.activate
def test_error_already_in_baseline_is_not_flagged(monkeypatch):
    # The page ALWAYS contains a SQL-error-looking string, injection or not.
    def cb(request):
        return (200, {"Content-Type": "text/html"}, "<html>ORA-00933: SQL command not properly ended (docs)</html>")

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert not any("SQL injection" in f.title for f in findings)


@responses.activate
def test_boolean_diff_within_noise_is_suppressed(monkeypatch):
    # Highly dynamic page: benign requests already differ a lot. A modest
    # true/false gap must NOT be reported.
    state = {"benign": 0}

    def cb(request):
        v = _val(request)
        if v == "1":
            state["benign"] += 1
            n = 1000 if state["benign"] == 1 else 2000  # noise = 1000
            return (200, {"Content-Type": "text/html"}, "A" * n)
        if v == "1 OR 1=1":
            return (200, {"Content-Type": "text/html"}, "A" * 1500)
        if v == "1 AND 1=2":
            return (200, {"Content-Type": "text/html"}, "A" * 1000)  # diff 500 < noise*4
        return (200, {"Content-Type": "text/html"}, "A" * 1000)

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert not any("blind SQLi" in f.title for f in findings)


@responses.activate
def test_boolean_clear_signal_is_flagged(monkeypatch):
    # Stable page (low noise) with a large true/false gap: genuine signal.
    def cb(request):
        v = _val(request)
        if v == "1":
            return (200, {"Content-Type": "text/html"}, "A" * 1000)  # base1 == base2, noise 0
        if v == "1 OR 1=1":
            return (200, {"Content-Type": "text/html"}, "A" * 4000)  # all rows
        if v == "1 AND 1=2":
            return (200, {"Content-Type": "text/html"}, "A" * 1000)  # no rows
        return (200, {"Content-Type": "text/html"}, "A" * 1000)

    responses.add_callback(responses.GET, re.compile(r"http://example\.com/.*"), callback=cb)
    findings = _run(monkeypatch)
    assert any(f.severity.value == "medium" and "blind SQLi" in f.title for f in findings)
