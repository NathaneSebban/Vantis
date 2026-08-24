"""Lightweight injection-point discovery for parameter-testing modules.

Given a target, this finds where user input flows into the app — the target
URL's own query parameters, plus parameters exposed by links and GET forms on
the landing page. The web modules (xss, sqli) fuzz these points instead of
guessing a fixed list against the origin, which is the difference between a
toy and a scanner that actually reaches real endpoints.

Deliberately conservative and polite:
- one page fetch (the landing page); no recursive crawl,
- only same-scope hosts are ever added (no wandering off-target / SSRF),
- results are capped and de-duplicated by (path, parameter).

HTML is parsed with regexes rather than pulling in a parser dependency; this is
good enough for discovering href/action/name attributes and keeps the tool
dependency-light. It is discovery only — never a correctness oracle.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?([a-zA-Z]+)""", re.IGNORECASE)
_NAME_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


@dataclass(frozen=True)
class InjectionPoint:
    """A single place to fuzz: a URL and the query parameter to vary."""
    url: str
    param: str
    method: str = "GET"
    source: str = "target"  # "target" | "link" | "form"


def set_param(url: str, param: str, value: str) -> str:
    """Return url with `param` set to `value`, preserving other query params."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def discover_injection_points(client, target, log=None, max_points: int = 25) -> list[InjectionPoint]:
    """Discover injection points for `target`. Returns [] if nothing is found
    (callers then fall back to their default parameter list)."""
    log = log or (lambda _m: None)
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, param: str, source: str) -> None:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Never leave the authorized scope.
        if not host or not target.is_in_scope(host):
            return
        # De-dupe per (path, param) so ?id=1 and ?id=2 don't both count.
        key = (parsed._replace(query="", fragment="").geturl(), param)
        if key in seen:
            return
        seen.add(key)
        points.append(InjectionPoint(url=url, param=param, source=source))

    # 1) The target URL's own parameters.
    for param in parse_qs(urlparse(target.url).query):
        add(target.url, param, "target")

    # 2) Crawl the landing page once for links and GET forms.
    resp = client.get(target.url)
    if resp is not None and resp.text and "html" in resp.headers.get("Content-Type", "").lower():
        html = resp.text

        for href in _HREF_RE.findall(html):
            absolute = urljoin(target.url, href)
            for param in parse_qs(urlparse(absolute).query):
                add(absolute, param, "link")
                if len(points) >= max_points:
                    break

        for form in _FORM_RE.findall(html):
            method = (_METHOD_RE.search(form).group(1).upper() if _METHOD_RE.search(form) else "GET")
            if method != "GET":
                # POST forms need a different request shape; out of scope for the
                # GET-based probes the modules use today.
                continue
            action_match = _ACTION_RE.search(form)
            action_url = urljoin(target.url, action_match.group(1)) if action_match and action_match.group(1) else target.url
            for name in _NAME_RE.findall(form):
                add(action_url, name, "form")
                if len(points) >= max_points:
                    break

    if points:
        log(f"discovered {len(points)} injection point(s)")
    return points[:max_points]
