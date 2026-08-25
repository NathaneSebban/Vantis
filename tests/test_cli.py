"""Tests for the CLI, focused on multi-target scanning."""
from vantis.cli import _output_path_for, main


def test_output_path_for_single_target_is_unchanged():
    assert _output_path_for("report.json", "example.com", multi=False) == "report.json"


def test_output_path_for_multi_target_inserts_slug():
    assert _output_path_for("report.json", "example.com", multi=True) == "report-example.com.json"


def test_output_path_for_none_stays_none():
    assert _output_path_for(None, "example.com", multi=True) is None


def test_output_path_for_sanitizes_target_slug():
    out = _output_path_for("report.json", "https://a.b/c?d=1", multi=True)
    assert out.startswith("report-") and out.endswith(".json")
    assert "/" not in out and "?" not in out


class _FakeReport:
    def __init__(self, findings=None):
        self.findings = findings or []

    def by_severity(self):
        return {"critical": [], "high": [], "medium": [], "low": [], "info": []}


class _FakeEngine:
    instances = []

    @staticmethod
    def confirm_authorization(target, assume_yes=False):
        pass

    def __init__(self, target, **kwargs):
        self.target = target
        self.kwargs = kwargs
        _FakeEngine.instances.append(self)

    def run(self):
        return _FakeReport()


def test_main_scans_every_comma_separated_target(monkeypatch):
    _FakeEngine.instances = []
    monkeypatch.setattr("vantis.cli.Engine", _FakeEngine)
    rc = main(["--target", "example.com,other.org", "--yes-i-am-authorized"])
    assert rc == 0
    assert [str(e.target) for e in _FakeEngine.instances] == ["http://example.com", "http://other.org"]


def test_main_continues_after_one_target_fails(monkeypatch):
    _FakeEngine.instances = []

    class _FailingThenOkEngine(_FakeEngine):
        def run(self):
            if "fail" in str(self.target):
                raise RuntimeError("boom")
            return _FakeReport()

    monkeypatch.setattr("vantis.cli.Engine", _FailingThenOkEngine)
    rc = main(["--target", "fail.example.com,ok.example.com", "--yes-i-am-authorized"])
    assert rc == 1  # one target failed, but the batch still completed
    assert len(_FailingThenOkEngine.instances) == 2
