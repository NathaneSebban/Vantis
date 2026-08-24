"""
Shared HTTP client: consistent timeouts, a clearly identifying
User-Agent (good practice for authorized security testing so target
owners can distinguish your traffic in logs), and basic rate limiting
so the scanner doesn't hammer the target.
"""
from __future__ import annotations

import time

import requests

DEFAULT_USER_AGENT = "Vantis/0.1 (+authorized-security-testing; contact=YOUR_EMAIL_HERE)"


class HttpClient:
    def __init__(self, timeout: float = 10.0, delay: float = 0.3, user_agent: str | None = None):
        self.timeout = timeout
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent or DEFAULT_USER_AGENT})
        self._last_request_ts = 0.0

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_ts = time.monotonic()

    def get(self, url: str, **kwargs) -> requests.Response | None:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", True)
        try:
            return self.session.get(url, **kwargs)
        except requests.RequestException:
            return None

    def post(self, url: str, **kwargs) -> requests.Response | None:
        self._throttle()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", True)
        try:
            return self.session.post(url, **kwargs)
        except requests.RequestException:
            return None
