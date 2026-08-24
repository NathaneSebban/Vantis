"""
Finding model and report generation (JSON, HTML, Markdown).
"""
from __future__ import annotations

import html
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    target: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    matched_at: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class Report:
    """Collects findings during a scan run and exports them."""

    def __init__(self, target: str):
        self.target = target
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.findings: list[Finding] = []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def by_severity(self) -> dict[str, list[Finding]]:
        buckets: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            buckets[f.severity.value].append(f)
        return buckets

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.weight, reverse=True)

    # -- Exporters ---------------------------------------------------

    def to_json(self, path: str | Path) -> None:
        data = {
            "target": self.target,
            "started_at": self.started_at,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    def to_markdown(self, path: str | Path) -> None:
        lines = [f"# Vantis Report — {self.target}", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", "", f"**Total findings:** {len(self.findings)}", ""]
        for sev in reversed(list(Severity)):
            group = [f for f in self.findings if f.severity == sev]
            if not group:
                continue
            lines.append(f"## {sev.value.upper()} ({len(group)})")
            lines.append("")
            for f in group:
                lines.append(f"### {f.title}")
                lines.append(f"- **Module:** {f.module}")
                lines.append(f"- **Location:** {f.matched_at or f.target}")
                if f.description:
                    lines.append(f"- **Description:** {f.description}")
                if f.evidence:
                    lines.append(f"- **Evidence:** `{f.evidence}`")
                if f.remediation:
                    lines.append(f"- **Remediation:** {f.remediation}")
                if f.references:
                    lines.append(f"- **References:** {', '.join(f.references)}")
                lines.append("")
        Path(path).write_text("\n".join(lines), encoding="utf-8")

    def to_html(self, path: str | Path) -> None:
        sev_colors = {
            "critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309",
            "low": "#1d4ed8", "info": "#374151",
        }
        # Escape every field derived from a finding: evidence/title/etc. can
        # contain content reflected from the scanned target (e.g. an XSS
        # payload). Without escaping, opening the report would execute it.
        rows = []
        for f in self.sorted_findings():
            color = sev_colors[f.severity.value]
            rows.append(f"""
            <tr>
              <td><span style="background:{color};color:#fff;padding:2px 8px;
                  border-radius:4px;font-size:12px;font-weight:600;">
                  {html.escape(f.severity.value.upper())}</span></td>
              <td>{html.escape(f.title)}</td>
              <td>{html.escape(f.module)}</td>
              <td>{html.escape(f.matched_at or f.target)}</td>
              <td>{html.escape(f.description)}</td>
            </tr>""")
        escaped_target = html.escape(self.target)
        html_doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Vantis Report — {escaped_target}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; margin: 40px; background:#f8fafc; color:#0f172a;}}
  h1 {{ font-size: 22px; }}
  table {{ border-collapse: collapse; width: 100%; background:#fff; box-shadow:0 1px 3px rgba(0,0,0,.1);}}
  th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; font-size: 14px; vertical-align: top;}}
  th {{ background:#0f172a; color:#fff; }}
  .meta {{ color:#64748b; margin-bottom: 20px; font-size: 13px;}}
</style></head>
<body>
  <h1>Vantis Report — {escaped_target}</h1>
  <div class="meta">Generated {datetime.now(timezone.utc).isoformat()} · {len(self.findings)} findings</div>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Module</th><th>Location</th><th>Description</th></tr>
    {''.join(rows)}
  </table>
</body></html>"""
        Path(path).write_text(html_doc, encoding="utf-8")

    def to_pdf(self, path: str | Path) -> None:
        """Render the report as a PDF.

        fpdf2 is an optional dependency (pure-Python, no native libraries) so
        the CLI-only install stays lean; it's imported here and a clear error
        is raised if it's missing. Install with the 'pdf' extra:
        pip install -e ".[pdf]".
        """
        try:
            from fpdf import FPDF
        except ImportError as e:  # pragma: no cover - exercised via the error path
            raise RuntimeError(
                "PDF export requires fpdf2. Install it with: pip install fpdf2 "
                "(or install Vantis with the 'pdf' extra: pip install -e '.[pdf]')."
            ) from e

        sev_colors = {
            "critical": (127, 29, 29), "high": (185, 28, 28), "medium": (180, 83, 9),
            "low": (29, 78, 216), "info": (55, 65, 81),
        }

        def s(text: str) -> str:
            # Core PDF fonts are latin-1; replace anything outside it so a
            # finding echoing exotic bytes from a target can't crash the export.
            return (text or "").encode("latin-1", "replace").decode("latin-1")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Header
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, s(f"Vantis Report - {self.target}"), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(100, 100, 100)
        pdf.cell(0, 5, s(f"Generated {datetime.now(timezone.utc).isoformat()}  -  {len(self.findings)} findings"),
                 new_x="LMARGIN", new_y="NEXT")

        # Severity summary
        counts = {sev.value: 0 for sev in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        pdf.ln(3)
        pdf.set_font("Helvetica", "B", 10)
        for sev in ["critical", "high", "medium", "low", "info"]:
            r, g, b = sev_colors[sev]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.cell(34, 7, s(f"{sev.upper()}: {counts[sev]}"), align="C", fill=True)
            pdf.cell(2, 7, "", new_x="RIGHT")
        pdf.ln(11)

        # Findings
        for f in self.sorted_findings():
            r, g, b = sev_colors[f.severity.value]
            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 8)
            pdf.cell(20, 6, s(f.severity.value.upper()), align="C", fill=True)
            pdf.set_text_color(15, 23, 42)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(3, 6, "", new_x="RIGHT")
            pdf.multi_cell(0, 6, s(f.title), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(80, 80, 80)

            def field(label: str, value: str) -> None:
                if not value:
                    return
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(24, 5, s(label), new_x="RIGHT")
                pdf.set_font("Helvetica", "", 9)
                pdf.multi_cell(0, 5, s(value), new_x="LMARGIN", new_y="NEXT")

            field("Module:", f.module)
            field("Location:", f.matched_at or f.target)
            field("Description:", f.description)
            field("Evidence:", f.evidence)
            field("Remediation:", f.remediation)
            if f.references:
                field("References:", ", ".join(f.references))
            pdf.ln(4)

        pdf.output(str(path))

    def to_sarif(self, path: str | Path) -> None:
        """Export SARIF 2.1.0 for CI/CD integration (e.g. GitHub code scanning).

        Severity maps to SARIF `level` (error/warning/note) plus a numeric
        `security-severity` GitHub uses to rank alerts.
        """
        level_map = {"critical": "error", "high": "error", "medium": "warning",
                     "low": "note", "info": "note"}
        sec_severity = {"critical": "9.5", "high": "8.0", "medium": "5.0", "low": "3.0", "info": "1.0"}

        rules: dict[str, dict] = {}
        results = []
        for f in self.sorted_findings():
            if f.module not in rules:
                rules[f.module] = {
                    "id": f.module,
                    "name": f.module,
                    "shortDescription": {"text": f.module},
                    "helpUri": (f.references[0] if f.references else "https://github.com/"),
                }
            results.append({
                "ruleId": f.module,
                "level": level_map.get(f.severity.value, "note"),
                "message": {"text": f"{f.title}. {f.description}".strip()},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.matched_at or f.target}
                    }
                }],
                "properties": {
                    "severity": f.severity.value,
                    "security-severity": sec_severity.get(f.severity.value, "1.0"),
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                },
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Vantis",
                    "informationUri": "https://github.com/NathaneSebban/Vantis",
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }},
                "results": results,
            }],
        }
        Path(path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
