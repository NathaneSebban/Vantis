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


_USERNAME_HINTS = ("user", "email", "login", "identifiant", "account")


def browser_login(login_url: str, username: str, password: str,
                   timeout_ms: int = 15000, log=None) -> dict[str, str] | None:
    """Log in via a real headless browser instead of parsing raw HTML.

    Fallback for JS-rendered (SPA) login forms: `auth_login.perform_login()`
    only sees the HTML the server sends, which for a React/Vue/Angular app is
    typically an empty `<div id="root">` — the real `<form>` only exists in
    the DOM after client-side JS renders it. This waits for that render, then
    interacts with the page like a real user: fill the password field (and
    whichever field looks like the username), submit, and read back the
    resulting cookies.

    Returns None on any failure (Playwright unavailable, no password field
    found even after rendering, submission didn't yield a new/changed
    cookie) — never raises, matching every other best-effort helper here."""
    log = log or (lambda _m: None)
    if not browser_crawl_available():
        log("headless browser unavailable (install: pip install vantis[browser] && playwright install chromium)")
        return None

    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.goto(login_url, timeout=timeout_ms, wait_until="domcontentloaded")

                before = {c["name"]: c["value"] for c in context.cookies()}

                # Wait for the password field to actually appear in the DOM —
                # SPA login forms are often rendered after an async fetch of
                # their own (lazy-loaded route, auth-config check, etc.), so
                # "the page loaded" isn't the same as "the form exists yet".
                try:
                    password_field = page.wait_for_selector(
                        'input[type="password"]', timeout=timeout_ms, state="visible"
                    )
                except Exception:
                    password_field = None
                if password_field is None:
                    log(f"no rendered login form found at {login_url} (checked after JS render)")
                    return None

                username_field = page.query_selector('input[type="email"]')
                if username_field is None:
                    for hint in _USERNAME_HINTS:
                        username_field = page.query_selector(
                            f'input[name*="{hint}" i], input[id*="{hint}" i]'
                        )
                        if username_field is not None:
                            break
                if username_field is None:
                    # Fall back to the first text-ish input on the page.
                    username_field = page.query_selector('input[type="text"], input:not([type])')
                if username_field is None:
                    log(f"rendered login form has a password field but no identifiable username field")
                    return None

                username_field.fill(username)
                password_field.fill(password)

                submit = page.query_selector('button[type="submit"], input[type="submit"]')
                if submit is not None:
                    submit.click()
                else:
                    password_field.press("Enter")

                page.wait_for_load_state("networkidle", timeout=timeout_ms)

                after = {c["name"]: c["value"] for c in context.cookies()}
                changed = {k: v for k, v in after.items() if before.get(k) != v}
                if not changed:
                    log("login submitted via headless browser but no session cookie changed — "
                        "credentials may be wrong")
                    return None

                log(f"headless-browser login succeeded, {len(changed)} cookie(s) obtained")
                return changed
            finally:
                browser.close()
    except Exception as e:  # noqa: BLE001 - best-effort; never break a scan over this
        log(f"headless-browser login failed: {e}")
        return None
