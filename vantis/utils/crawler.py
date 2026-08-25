"""Injection-point discovery (light crawler).

Given a target, this finds where user input flows into the app so the web
modules (xss, sqli, path-traversal, ssti, open-redirect) can fuzz real
endpoints instead of guessing. Sources, in order of trust:

- the target URL's own query parameters,
- links and GET forms on the landing page,
- one level of same-scope links (bounded BFS),
- URLs advertised in robots.txt and sitemap.xml,
- historical URLs from the Wayback Machine (passive OSINT; best-effort).

Conservative and polite: bounded page budget, only same-scope hosts are ever
added (no wandering off-target / SSRF), and results are capped and de-duplicated
by (path, parameter). HTML is parsed with regexes to stay dependency-light.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

_HREF_RE = re.compile(r"""href\s*=\s*["']([^"'#\s]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>.*?</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']?([a-zA-Z]+)""", re.IGNORECASE)
_NAME_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_ROBOTS_PATH_RE = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.IGNORECASE | re.MULTILINE)


@dataclass(frozen=True)
class InjectionPoint:
    """A single place to fuzz: a URL and the query parameter to vary."""
    url: str
    param: str
    method: str = "GET"
    source: str = "target"  # target | link | form | crawl | sitemap | wayback


def set_param(url: str, param: str, value: str) -> str:
    """Return url with `param` set to `value`, preserving other query params."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


def _in_scope(target, url: str) -> bool:
    host = urlparse(url).hostname or ""
    return bool(host) and target.is_in_scope(host)


def _extract_from_html(html: str, page_url: str):
    """Yield (url, param, source) from links and GET forms in one page."""
    for href in _HREF_RE.findall(html):
        absolute = urljoin(page_url, href)
        for param in parse_qs(urlparse(absolute).query):
            yield absolute, param, "link"
    for form in _FORM_RE.findall(html):
        method = (_METHOD_RE.search(form).group(1).upper() if _METHOD_RE.search(form) else "GET")
        if method != "GET":
            continue  # POST forms need a different request shape (handled elsewhere)
        action_match = _ACTION_RE.search(form)
        action_url = urljoin(page_url, action_match.group(1)) if action_match and action_match.group(1) else page_url
        for name in _NAME_RE.findall(form):
            yield action_url, name, "form"


def _same_scope_links(html: str, page_url: str, target) -> list[str]:
    out: list[str] = []
    for href in _HREF_RE.findall(html):
        absolute = urljoin(page_url, href)
        p = urlparse(absolute)
        if p.scheme in ("http", "https") and _in_scope(target, absolute):
            out.append(urlunparse(p._replace(fragment="")))
    return out


def _robots_sitemap_urls(client, target, log) -> list[str]:
    """Seed URLs advertised by robots.txt and sitemap.xml (same scope only)."""
    base = target.base_url
    urls: list[str] = []
    robots = client.get(f"{base}/robots.txt")
    if robots is not None and robots.status_code == 200 and robots.text:
        for path in _ROBOTS_PATH_RE.findall(robots.text):
            if path and path != "/":
                urls.append(urljoin(base + "/", path.lstrip("/")))
    for sm in (f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"):
        resp = client.get(sm)
        if resp is not None and resp.status_code == 200 and resp.text:
            urls.extend(_SITEMAP_LOC_RE.findall(resp.text))
    scoped = [u for u in urls if _in_scope(target, u)]
    if scoped:
        log(f"robots/sitemap advertised {len(scoped)} url(s)")
    return scoped


def _wayback_urls(client, target, log, limit: int = 100) -> list[str]:
    """Historical URLs (with query strings) for the host, from the Wayback
    Machine. Passive — hits web.archive.org, never the target. Best-effort."""
    host = target.host
    api = (f"https://web.archive.org/cdx/search/cdx?url={host}/*&output=json"
           f"&fl=original&collapse=urlkey&filter=statuscode:200&limit={limit}")
    resp = client.get(api)
    if resp is None or resp.status_code != 200 or not resp.text:
        return []
    try:
        rows = json.loads(resp.text)
    except ValueError:
        return []
    urls = [r[0] for r in rows[1:] if r and "?" in r[0]]  # skip header row; only param'd URLs
    scoped = [u for u in urls if _in_scope(target, u)]
    if scoped:
        log(f"wayback returned {len(scoped)} historical param URL(s)")
    return scoped


def discover_injection_points(
    client,
    target,
    log=None,
    max_points: int = 25,
    max_pages: int = 8,
    use_wayback: bool = True,
    use_browser: bool = False,
) -> list[InjectionPoint]:
    """Discover injection points for `target`. Returns [] if nothing is found
    (callers then fall back to their default parameter list)."""
    log = log or (lambda _m: None)
    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()

    def add(url: str, param: str, source: str) -> None:
        if not _in_scope(target, url):
            return
        key = (urlparse(url)._replace(query="", fragment="").geturl(), param)
        if key in seen:
            return
        seen.add(key)
        points.append(InjectionPoint(url=url, param=param, source=source))

    # 1) target's own params
    for param in parse_qs(urlparse(target.url).query):
        add(target.url, param, "target")

    # 2) passive seed URLs (robots/sitemap/wayback) contribute params directly
    seed_urls: list[str] = []
    try:
        seed_urls += _robots_sitemap_urls(client, target, log)
        if use_wayback:
            seed_urls += _wayback_urls(client, target, log)
    except Exception as e:  # noqa: BLE001 - discovery must never break a scan
        log(f"passive discovery error: {e}")
    for u in seed_urls:
        for param in parse_qs(urlparse(u).query):
            add(u, param, "sitemap")

    # 2b) OpenAPI/Swagger spec, if exposed: exact, complete knowledge of every
    # endpoint/parameter beats guessing from crawled HTML. Highest-value
    # source when present, so it's always attempted (a couple of cheap GETs).
    try:
        from vantis.utils.openapi_crawler import discover_openapi, openapi_injection_points

        spec, spec_url = discover_openapi(client, target, log)
        if spec is not None:
            for p in openapi_injection_points(spec, target.base_url):
                add(p.url, p.param, p.source)
    except Exception as e:  # noqa: BLE001 - discovery must never break a scan
        log(f"OpenAPI discovery error: {e}")

    # 3) bounded BFS over same-scope HTML pages, starting at the landing page
    queue: list[str] = [target.url]
    visited: set[str] = set()
    while queue and len(visited) < max_pages and len(points) < max_points:
        page_url = queue.pop(0)
        norm = urlparse(page_url)._replace(fragment="").geturl()
        if norm in visited:
            continue
        visited.add(norm)
        resp = client.get(page_url)
        if resp is None or not resp.text or "html" not in resp.headers.get("Content-Type", "").lower():
            continue
        for url, param, source in _extract_from_html(resp.text, page_url):
            add(url, param, source)
            if len(points) >= max_points:
                break
        # enqueue one more level of same-scope links
        for link in _same_scope_links(resp.text, page_url, target):
            if urlparse(link)._replace(fragment="").geturl() not in visited:
                queue.append(link)

    # 4) headless-browser rendering: catches SPA content the static crawler
    # can never see (client-side-rendered links/forms) and, most valuably,
    # the real XHR/fetch API calls the app makes on load. Optional — a real
    # browser is slow, so this only runs when explicitly requested.
    if use_browser and len(points) < max_points:
        try:
            from vantis.utils.browser_crawler import browser_crawl

            for bp in browser_crawl(target, max_points=max_points - len(points)):
                add(bp.url, bp.param, bp.source)
        except Exception as e:  # noqa: BLE001 - discovery must never break a scan
            log(f"browser crawl error: {e}")

    if points:
        log(f"discovered {len(points)} injection point(s)")
    return points[:max_points]
