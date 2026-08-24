"""API tests for the Vantis REST layer.

Scans run against a *fake* engine so tests never touch the network: the fake
emits deterministic findings through the same progress-callback contract the
real engine uses, exercising persistence, filtering, reporting, cancellation
and the live WebSocket end to end.
"""
from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import app
from vantis.core.report import Finding, Severity

# Gate the fake engine so the WebSocket test can connect *before* any event is
# emitted (otherwise early events race the socket and are lost).
_RELEASE = threading.Event()


class FakeEngine:
    """Stand-in for vantis.core.engine.Engine that emits scripted events."""

    def __init__(self, target, categories=None, http_timeout=10.0, rate_limit_delay=0.3,
                 verbose=False, auth_headers=None, auth_cookies=None, max_workers=1):
        self.target = target
        self.categories = categories or []

    def run(self, progress_callback=None):
        _RELEASE.wait(timeout=5)
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
    _RELEASE.set()  # by default, don't block; the WS test clears it itself
    monkeypatch.setattr("api.scan_runner.Engine", FakeEngine)


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _wait_for_status(client, scan_id, statuses, timeout=5.0, headers=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/scans/{scan_id}", headers=headers or {})
        if r.status_code == 200 and r.json()["status"] in statuses:
            return r.json()
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not reach {statuses}")


# -- authorization gate ----------------------------------------------

def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_scan_refused_without_authorization(client):
    r = client.post("/api/scans", json={"target": "https://example.com", "authorized": False})
    assert r.status_code == 400
    assert "authoriz" in r.json()["detail"].lower()


def test_scan_refused_when_authorization_absent(client):
    # authorized is a required field -> pydantic 422
    r = client.post("/api/scans", json={"target": "https://example.com"})
    assert r.status_code == 422


def test_scan_rejects_implausible_target(client):
    r = client.post("/api/scans", json={"target": "not a url at all!!", "authorized": True})
    assert r.status_code == 422


def test_scan_rejects_unknown_module(client):
    r = client.post("/api/scans", json={"target": "https://example.com", "authorized": True, "modules": ["bogus"]})
    assert r.status_code == 422


# -- full scan lifecycle ---------------------------------------------

def test_full_scan_flow(client):
    r = client.post("/api/scans", json={
        "target": "https://example.com",
        "scope": ["example.com"],
        "modules": ["web"],
        "authorized": True,
    })
    assert r.status_code == 202
    scan_id = r.json()["scan_id"]
    assert r.json()["status"] == "queued"

    detail = _wait_for_status(client, scan_id, {"completed"})
    assert detail["findings_count"] == 2
    assert detail["severity_counts"]["high"] == 1
    assert detail["severity_counts"]["low"] == 1

    # findings, unfiltered
    findings = client.get(f"/api/scans/{scan_id}/findings").json()
    assert len(findings) == 2
    assert findings[0]["severity"] == "high"  # sorted, highest first

    # severity filter
    high_only = client.get(f"/api/scans/{scan_id}/findings?severity=high").json()
    assert len(high_only) == 1 and high_only[0]["module"] == "reflected-xss"

    # module filter
    hdr = client.get(f"/api/scans/{scan_id}/findings?module=security-headers").json()
    assert len(hdr) == 1 and hdr[0]["severity"] == "low"

    # reports in each format
    for fmt, needle in [("json", b"reflected-xss"), ("html", b"<table"), ("md", b"# Vantis Report"), ("pdf", b"%PDF-")]:
        rep = client.get(f"/api/scans/{scan_id}/report?format={fmt}")
        assert rep.status_code == 200
        assert needle in rep.content
        assert "attachment" in rep.headers["content-disposition"]
    assert client.get(f"/api/scans/{scan_id}/report?format=pdf").headers["content-type"] == "application/pdf"

    # history list
    listing = client.get("/api/scans").json()
    assert listing["total"] >= 1
    assert any(item["scan_id"] == scan_id for item in listing["items"])


def test_delete_completed_scan_removes_history(client):
    r = client.post("/api/scans", json={"target": "https://example.com", "authorized": True, "modules": ["web"]})
    scan_id = r.json()["scan_id"]
    _wait_for_status(client, scan_id, {"completed"})

    d = client.delete(f"/api/scans/{scan_id}")
    assert d.status_code == 200 and d.json()["action"] == "deleted"
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_get_missing_scan_is_404(client):
    assert client.get("/api/scans/does-not-exist").status_code == 404


# -- optional hardening (opt-in via settings) ------------------------

def test_api_key_enforced_when_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "api_key", "s3cret")
    body = {"target": "https://example.com", "authorized": True, "modules": ["web"]}

    # Missing key -> 401.
    assert client.post("/api/scans", json=body).status_code == 401
    # Wrong key -> 401.
    assert client.post("/api/scans", headers={"X-API-Key": "nope"}, json=body).status_code == 401
    # Correct key -> accepted.
    ok = client.post("/api/scans", headers={"X-API-Key": "s3cret"}, json=body)
    assert ok.status_code == 202
    # Reads are protected too.
    assert client.get("/api/scans").status_code == 401
    assert client.get("/api/scans", headers={"X-API-Key": "s3cret"}).status_code == 200

    # Let the (fake) engine finish before teardown restores the real Engine, so
    # the background worker never runs a real scan.
    scan_id = ok.json()["scan_id"]
    _wait_for_status(client, scan_id, {"completed"}, headers={"X-API-Key": "s3cret"})


def test_private_target_blocked_when_enabled(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "block_private_targets", True)

    for blocked in ("http://127.0.0.1", "http://169.254.169.254", "http://10.0.0.5", "http://localhost"):
        r = client.post("/api/scans", json={"target": blocked, "authorized": True, "modules": ["web"]})
        assert r.status_code == 422, f"{blocked} should be blocked"

    # A public target is still accepted.
    ok = client.post("/api/scans", json={"target": "https://example.com", "authorized": True, "modules": ["web"]})
    assert ok.status_code == 202
    # Drain the fake scan before teardown (avoid a real background scan).
    _wait_for_status(client, ok.json()["scan_id"], {"completed"})


# -- live WebSocket ---------------------------------------------------

def test_websocket_streams_events(client):
    _RELEASE.clear()  # make the fake engine block until we've connected
    try:
        r = client.post("/api/scans", json={"target": "https://example.com", "authorized": True, "modules": ["web"]})
        scan_id = r.json()["scan_id"]

        with client.websocket_connect(f"/api/scans/{scan_id}/live") as ws:
            _RELEASE.set()  # release the engine now that the socket is live
            types, findings = [], 0
            for _ in range(20):
                msg = ws.receive_json()
                types.append(msg["type"])
                if msg["type"] == "finding":
                    findings += 1
                if msg["type"] == "scan_end":
                    break
            assert "finding" in types
            assert "scan_end" in types
            assert findings == 2
    finally:
        _RELEASE.set()
