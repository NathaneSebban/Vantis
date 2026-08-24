from vantis.modules.cve.template_engine import Template


def test_template_from_dict():
    data = {
        "id": "test-template",
        "info": {"name": "Test", "severity": "high", "description": "desc"},
        "request": {"method": "GET", "path": "/foo"},
        "matchers": {"status": [200], "body_contains": ["marker"]},
    }
    t = Template.from_dict(data)
    assert t.id == "test-template"
    assert t.path == "/foo"
    assert t.matches(200, "some marker here", {})
    assert not t.matches(404, "some marker here", {})
    assert not t.matches(200, "no match here", {})


def test_template_header_matcher():
    data = {
        "id": "header-test",
        "info": {"name": "Header Test", "severity": "low"},
        "request": {"path": "/"},
        "matchers": {"header": {"Server": "nginx"}},
    }
    t = Template.from_dict(data)
    assert t.matches(200, "", {"Server": "nginx/1.18.0"})
    assert not t.matches(200, "", {"Server": "Apache"})


def test_template_without_matchers_never_matches():
    data = {
        "id": "no-matchers",
        "info": {"name": "No matchers", "severity": "info"},
        "request": {"path": "/"},
        "matchers": {},
    }
    t = Template.from_dict(data)
    assert not t.matches(200, "anything", {})
