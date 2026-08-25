"""Engine surfaces the automated-login outcome as a Finding, visible in the
live feed and every report export — not just a server-side log line."""
import responses

from vantis.core.engine import Engine
from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding, Severity
from vantis.core.target import Target

LOGIN_PAGE = """
<form action="/do-login" method="post">
  <input type="text" name="email">
  <input type="password" name="password">
</form>
"""


class _NoOpModule(ScanModule):
    name = "noop"
    category = "web"

    def run(self):
        return []


def _engine(**login_kwargs):
    eng = Engine(target=Target("http://example.com"), categories=["web"], max_workers=1, **login_kwargs)
    eng._modules = [_NoOpModule]  # skip discovery; nothing else to run
    return eng


@responses.activate
def test_successful_login_produces_an_info_finding():
    responses.add(responses.GET, "http://example.com/login", body=LOGIN_PAGE, status=200)
    responses.add(responses.POST, "http://example.com/do-login", status=200,
                   headers={"Set-Cookie": "session=abc123; Path=/"})

    report = _engine(
        login_url="http://example.com/login", login_username="a@b.com", login_password="pw",
    ).run()

    login_findings = [f for f in report.findings if f.module == "auth-login"]
    assert len(login_findings) == 1
    f = login_findings[0]
    assert f.severity == Severity.INFO
    assert "succeeded" in f.title.lower()
    assert "1 session cookie" in f.description


@responses.activate
def test_failed_login_produces_a_low_severity_finding_with_a_reason():
    responses.add(responses.GET, "http://example.com/login", body=LOGIN_PAGE, status=200)
    responses.add(responses.POST, "http://example.com/do-login", status=200)  # no Set-Cookie -> failure

    report = _engine(
        login_url="http://example.com/login", login_username="a@b.com", login_password="wrong",
    ).run()

    login_findings = [f for f in report.findings if f.module == "auth-login"]
    assert len(login_findings) == 1
    f = login_findings[0]
    assert f.severity == Severity.LOW
    assert "failed" in f.title.lower()
    assert "credentials may be wrong" in f.description
    assert "UNAUTHENTICATED" in f.remediation


def test_no_login_finding_when_login_not_configured():
    report = _engine().run()
    assert [f for f in report.findings if f.module == "auth-login"] == []


@responses.activate
def test_login_finding_is_streamed_via_progress_callback():
    responses.add(responses.GET, "http://example.com/login", body=LOGIN_PAGE, status=200)
    responses.add(responses.POST, "http://example.com/do-login", status=200,
                   headers={"Set-Cookie": "session=abc123; Path=/"})

    events = []

    def cb(evt, payload):
        events.append((evt, payload.get("module")))

    _engine(login_url="http://example.com/login", login_username="a@b.com", login_password="pw").run(
        progress_callback=cb
    )

    assert ("finding", "auth-login") in events
    # The login finding is emitted before any module_start, so a client sees
    # it immediately rather than buried after the first module completes.
    assert events.index(("finding", "auth-login")) < [e[0] for e in events].index("module_start")
