"""Tests for version -> CVE mapping."""
import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.cve.version_cve import (
    VersionCveModule,
    known_cves_for,
    products_from_headers,
)


def test_vulnerable_version_matches():
    hits = known_cves_for("nginx", "1.18.0")
    assert any(c["cve"] == "CVE-2021-23017" for c in hits)


def test_patched_version_has_no_match():
    assert known_cves_for("nginx", "1.25.0") == []


def test_range_constraint_apache():
    # 2.4.49 is in the vulnerable range for CVE-2021-41773 (>=2.4.49, <=2.4.50)
    assert any(c["cve"] == "CVE-2021-41773" for c in known_cves_for("apache", "2.4.49"))
    # 2.4.52 is out of that specific range
    assert not any(c["cve"] == "CVE-2021-41773" for c in known_cves_for("apache", "2.4.52"))


def test_unknown_product_is_empty():
    assert known_cves_for("lighttpd", "1.4.0") == []


def test_header_parsing():
    pairs = products_from_headers({"Server": "Apache/2.4.49 (Ubuntu)", "X-Powered-By": "PHP/8.1.2"})
    assert ("Apache", "2.4.49") in pairs
    assert ("PHP", "8.1.2") in pairs


@responses.activate
def test_module_reports_from_server_header():
    responses.add(responses.GET, "http://example.com", body="ok", status=200,
                  headers={"Server": "nginx/1.18.0"})
    ctx = ModuleContext(target=Target("http://example.com"), rate_limit_delay=0)
    findings = VersionCveModule(ctx).run()
    assert any("CVE-2021-23017" in f.evidence for f in findings)
