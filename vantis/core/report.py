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
<html lang="fr"><head><meta charset="utf-8">
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
