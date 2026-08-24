"""Tests for subdomain enumeration scoping."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.recon.subdomain_enum import SubdomainEnumModule


@responses.activate
def test_sibling_domain_is_not_treated_as_subdomain():
    # crt.sh returns real subdomains, the apex, a wildcard, a SIBLING domain
    # owned by someone else, and an unrelated domain.
    responses.add(
        responses.GET,
        re.compile(r"https://crt\.sh/.*"),
        json=[
            {"name_value": "api.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
            {"name_value": "example.com"},
            {"name_value": "evilexample.com"},   # sibling — must be excluded
            {"name_value": "unrelated.org"},
        ],
        status=200,
    )
    ctx = ModuleContext(target=Target("https://example.com"), rate_limit_delay=0)
    findings = SubdomainEnumModule(ctx).run()

    assert len(findings) == 1
    discovered = findings[0].evidence.splitlines()
    assert "api.example.com" in discovered
    assert "www.example.com" in discovered
    assert "evilexample.com" not in discovered   # the bug this guards against
    assert "unrelated.org" not in discovered
    # extra_hosts (fed to later modules) must also exclude the sibling.
    assert "evilexample.com" not in (ctx.extra_hosts or [])


@responses.activate
def test_crtsh_unreachable_returns_no_findings():
    responses.add(responses.GET, re.compile(r"https://crt\.sh/.*"), status=502)
    ctx = ModuleContext(target=Target("https://example.com"), rate_limit_delay=0)
    assert SubdomainEnumModule(ctx).run() == []
