"""
Wires the template engine into the plugin system as a regular
ScanModule, so the engine's discovery/ordering logic treats it like
any other module.
"""
from __future__ import annotations

from pathlib import Path

from vantis.core.plugin_base import ScanModule
from vantis.core.report import Finding
from vantis.modules.cve.template_engine import load_templates, run_templates
from vantis.utils.http_client import HttpClient

TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates" / "cve"


class CveTemplateModule(ScanModule):
    name = "cve-templates"
    category = "cve"
    description = "Run YAML-based detection templates for known CVEs/misconfigurations"

    def run(self) -> list[Finding]:
        templates = load_templates(TEMPLATES_DIR)
        if not templates:
            self.log(f"No templates found in {TEMPLATES_DIR}")
            return []

        client = self.ctx.new_http_client()
        return run_templates(str(self.ctx.target), templates, client)
