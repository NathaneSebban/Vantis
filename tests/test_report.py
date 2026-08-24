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


def test_pdf_export(tmp_path: Path):
    r = make_report()
    # Include non-latin-1 content to ensure the exporter sanitizes instead of
    # crashing on exotic bytes a finding might echo from a target.
    r.add(Finding(module="tech-detect", title="Unicode ✓ é 日本語 test", severity=Severity.INFO,
                  target="example.com", evidence="server: nginx/1.24.0"))
    out = tmp_path / "report.pdf"
    r.to_pdf(out)
    data = out.read_bytes()
    assert data[:5] == b"%PDF-"       # valid PDF header
    assert len(data) > 500            # non-trivial content


def test_sarif_export(tmp_path: Path):
    r = make_report()
    out = tmp_path / "report.sarif"
    r.to_sarif(out)
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "Vantis"
    assert len(run["results"]) == 3
    # critical -> error level, with a numeric security-severity for GitHub.
    crit = next(res for res in run["results"] if res["properties"]["severity"] == "critical")
    assert crit["level"] == "error"
    assert crit["properties"]["security-severity"] == "9.5"


def test_html_export_escapes_finding_fields(tmp_path: Path):
    # A finding can carry content reflected from the scanned target. The HTML
    # report must escape it so opening the report never executes injected markup.
    r = Report(target="example.com")
    r.add(Finding(
        module="reflected-xss",
        title="<script>alert(1)</script>",
        severity=Severity.HIGH,
        target="example.com",
        description="param <img src=x onerror=alert(1)>",
    ))
    out = tmp_path / "report.html"
    r.to_html(out)
    content = out.read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "onerror=alert(1)>" not in content
