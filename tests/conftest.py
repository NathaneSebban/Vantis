"""Shared pytest setup.

Point the API at an isolated temp SQLite file and raise the scan rate limit
*before* anything imports the api package — get_settings() and the rate-limit
decorator both read these at import time.
"""
import os
import tempfile
import threading

import pytest

_TEST_DB = os.path.join(tempfile.gettempdir(), "vantis_test.db")
os.environ.setdefault("VANTIS_DATABASE_URL", f"sqlite:///{_TEST_DB}")
os.environ.setdefault("VANTIS_SCAN_RATE_LIMIT", "1000/hour")

# Start each session from a clean database file.
if os.path.exists(_TEST_DB):
    try:
        os.remove(_TEST_DB)
    except OSError:
        pass

# Gate the fake engine so a WebSocket test can connect *before* any event is
# emitted (otherwise early events race the socket and are lost). Shared across
# every test module — see FakeEngine below.
RELEASE = threading.Event()


class FakeEngine:
    """Stand-in for vantis.core.engine.Engine that emits scripted events, so
    the test suite never touches the network."""

    def __init__(self, target, categories=None, http_timeout=10.0, rate_limit_delay=0.3,
                 verbose=False, auth_headers=None, auth_cookies=None,
                 secondary_auth_headers=None, secondary_auth_cookies=None, max_workers=1,
                 enabled_modules=None, browser_crawl=False, login_url=None,
                 login_username=None, login_password=None):
        self.target = target
        self.categories = categories or []

    def run(self, progress_callback=None):
        from vantis.core.report import Finding, Severity

        RELEASE.wait(timeout=5)
        findings = [
            Finding(module="reflected-xss", title="Reflected XSS", severity=Severity.HIGH,
                    target=str(self.target), description="param echoed", matched_at="?q="),
            Finding(module="security-headers", title="Missing CSP", severity=Severity.LOW,
                    target=str(self.target), description="no CSP header"),
        ]
        total = 2
        progress_callback and progress_callback("module_start", {"module": "reflected-xss", "category": "web", "index": 1, "total": total})
        progress_callback and progress_callback("finding", {"module": "reflected-xss", "finding": findings[0]})
        progress_callback and progress_callback("module_end", {"module": "reflected-xss", "count": 1, "index": 1, "total": total})
        progress_callback and progress_callback("module_start", {"module": "security-headers", "category": "web", "index": 2, "total": total})
        progress_callback and progress_callback("finding", {"module": "security-headers", "finding": findings[1]})
        progress_callback and progress_callback("module_end", {"module": "security-headers", "count": 1, "index": 2, "total": total})
        progress_callback and progress_callback("scan_end", {"total_findings": total})
        return None


@pytest.fixture(autouse=True)
def _patch_engine(monkeypatch):
    RELEASE.set()  # by default, don't block; the WS test clears it itself
    monkeypatch.setattr("api.scan_runner.Engine", FakeEngine)
