"""
Headless-browser crawling (Playwright), for JavaScript-rendered apps.

The regex-based crawler in `crawler.py` only sees the HTML the server sends —
it never sees content a React/Vue/Angular app renders client-side. This module
loads the page in a real (headless) browser and:

1. Extracts links/forms from the FULLY RENDERED DOM (post-JS), catching
   navigation the static crawler misses entirely.
2. Records every XHR/fetch request the page makes while loading — this is the
   single highest-value signal for modern apps: it reveals the actual API
   endpoints and their parameters, which no static crawler can find by
   guessing.

Optional dependency: `pip install playwright && playwright install chromium`.
Gracefully unavailable (returns no points, never raises) if not installed —
mirrors how the PDF exporter handles its own optional dependency.

Detection only: navigates and observes: it fills no forms and submits nothing
beyond the initial page load, so it never causes a state change on the target.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import parse_qs, urljoin, urlparse

from vantis.utils.crawler import InjectionPoint


def browser_crawl_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except ImportError:
        return False


@dataclass(frozen=True)
class CapturedRequest:
    """A network request observed while the page loaded/ran."""
    url: str
    method: str


def _extract_points_from_url(url: str, source: str, target, seen: set, points: list) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host or not target.is_in_scope(host):
        return
    for param in parse_qs(parsed.query):
        key = (parsed._replace(query="", fragment="").geturl(), param)
        if key in seen:
            continue
        seen.add(key)
        points.append(InjectionPoint(url=url, param=param, source=source))


def browser_crawl(target, timeout_ms: int = 15000, max_points: int = 40) -> list[InjectionPoint]:
    """Render the target in headless Chromium and return discovered injection
    points from both the rendered DOM and captured XHR/fetch calls.

    Returns [] on any failure (browser not installed, page fails to load,
    timeout) — this is a best-effort enhancement layered on top of the
    always-available static crawler, never a hard dependency."""
    if not browser_crawl_available():
        return []

    from playwright.sync_api import sync_playwright

    points: list[InjectionPoint] = []
    seen: set[tuple[str, str]] = set()
    captured_urls: list[CapturedRequest] = []

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                # Record every network request the page issues while it loads
                # and runs its startup JS — this is how we see the real API
                # calls an SPA makes, which a static HTML crawler can't find.
                def on_request(req):
                    if req.resource_type in ("xhr", "fetch"):
                        captured_urls.append(CapturedRequest(url=req.url, method=req.method))

                page.on("request", on_request)
                page.goto(target.url, timeout=timeout_ms, wait_until="networkidle")

                # 1) Links + query params from the fully rendered DOM.
                hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for href in hrefs:
                    _extract_points_from_url(href, "browser-link", target, seen, points)
                    if len(points) >= max_points:
                        break

                # 2) Form fields from the rendered DOM (GET forms only, same
                # constraint as the static crawler).
                forms = page.eval_on_selector_all(
                    "form",
                    """els => els.map(f => ({
                        action: f.action, method: (f.method || 'get').toLowerCase(),
                        fields: [...f.querySelectorAll('input[name],textarea[name],select[name]')].map(i => i.name)
                    }))""",
                )
                for form in forms:
                    if form.get("method") != "get":
                        continue
                    action = form.get("action") or target.url
                    for name in form.get("fields", []):
                        if len(points) >= max_points:
                            break
                        absolute = urljoin(target.url, action)
                        parsed = urlparse(absolute)
                        host = parsed.hostname or ""
                        if host and target.is_in_scope(host):
                            key = (parsed._replace(query="", fragment="").geturl(), name)
                            if key not in seen:
                                seen.add(key)
                                points.append(InjectionPoint(url=absolute, param=name, source="browser-form"))
            finally:
                browser.close()
    except Exception:  # noqa: BLE001 - best-effort; never break a scan over this
        pass

    # 3) Captured XHR/fetch calls — the highest-signal source for SPA APIs.
    for req in captured_urls:
        if len(points) >= max_points:
            break
        _extract_points_from_url(req.url, "browser-xhr", target, seen, points)

    return points[:max_points]
