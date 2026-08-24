import json
from pathlib import Path

from vantis.core.report import Finding, Report, Severity


def make_report() -> Report:
    r = Report(target="example.com")
    r.add(Finding(module="mod-a", title="Low issue", severity=Severity.LOW, target="example.com"))
    r.add(Finding(module="mod-b", title="Critical issue", severity=Severity.CRITICAL, target="example.com"))
    r.add(Finding(module="mod-c", title="Medium issue", severity=Severity.MEDIUM, target="example.com"))
    return r


def test_sorted_findings_puts_critical_first():
    r = make_report()
    sorted_findings = r.sorted_findings()
    assert sorted_findings[0].severity == Severity.CRITICAL
    assert sorted_findings[-1].severity == Severity.LOW


def test_by_severity_buckets():
    r = make_report()
    buckets = r.by_severity()
    assert len(buckets["critical"]) == 1
    assert len(buckets["low"]) == 1
    assert len(buckets["high"]) == 0


def test_json_export(tmp_path: Path):
    r = make_report()
    out = tmp_path / "report.json"
    r.to_json(out)
    data = json.loads(out.read_text())
    assert data["total_findings"] == 3
    assert data["findings"][0]["severity"] == "critical"


def test_markdown_export(tmp_path: Path):
    r = make_report()
    out = tmp_path / "report.md"
    r.to_markdown(out)
    content = out.read_text()
    assert "Critical issue" in content
    assert "# Vantis Report" in content


def test_html_export(tmp_path: Path):
    r = make_report()
    out = tmp_path / "report.html"
    r.to_html(out)
    content = out.read_text()
    assert "<html" in content
    assert "Critical issue" in content
