"""Anonymous per-visitor isolation (api/ownership.py): two browsers — two
separate TestClient instances, each with its own cookie jar — must never see
or touch each other's scans or schedules. No accounts, no login: isolation is
enforced purely by the httpOnly session cookie minted on first request."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from api.main import app

# Reuses the same FakeEngine patch as test_api.py via the autouse fixture
# defined there (pytest applies autouse fixtures from every collected module).


def _wait_for_status(client, scan_id, statuses, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/scans/{scan_id}")
        if r.status_code == 200 and r.json()["status"] in statuses:
            return r.json()
        time.sleep(0.05)
    raise AssertionError(f"scan {scan_id} did not reach {statuses}")


@pytest.fixture
def alice():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def bob():
    with TestClient(app) as c:
        yield c


def test_first_request_mints_a_session_cookie(alice):
    # /api/health carries no per-visitor data, so it never touches get_owner_id
    # — use an endpoint that does (listing scans) to observe the cookie.
    r = alice.get("/api/scans")
    assert "vantis_sid" in r.cookies
    sid = r.cookies["vantis_sid"]
    # Stable across subsequent requests, not re-minted every time.
    alice.get("/api/scans")
    assert alice.cookies["vantis_sid"] == sid


def test_two_visitors_have_independent_scan_history(alice, bob):
    a = alice.post("/api/scans", json={"target": "https://alice.example.com", "authorized": True, "modules": ["web"]})
    scan_id = a.json()["scan_id"]
    _wait_for_status(alice, scan_id, {"completed"})

    # Bob's list is empty — Alice's scan doesn't leak into it.
    assert bob.get("/api/scans").json()["items"] == []
    # Alice sees her own.
    assert any(i["scan_id"] == scan_id for i in alice.get("/api/scans").json()["items"])

    # Bob can't fetch Alice's scan by id either — 404, not 403 (existence isn't leaked).
    assert bob.get(f"/api/scans/{scan_id}").status_code == 404
    assert bob.get(f"/api/scans/{scan_id}/findings").status_code == 404
    assert bob.delete(f"/api/scans/{scan_id}").status_code == 404

    # Alice's own access still works.
    assert alice.get(f"/api/scans/{scan_id}").status_code == 200


def test_target_trend_is_scoped_per_visitor(alice, bob):
    target = "https://shared-target.example.com"
    a = alice.post("/api/scans", json={"target": target, "authorized": True, "modules": ["web"]})
    _wait_for_status(alice, a.json()["scan_id"], {"completed"})
    b = bob.post("/api/scans", json={"target": target, "authorized": True, "modules": ["web"]})
    _wait_for_status(bob, b.json()["scan_id"], {"completed"})

    # Same target string, but each visitor's trend only contains their own scan.
    alice_trend = alice.get(f"/api/scans/trend?target={target}").json()
    bob_trend = bob.get(f"/api/scans/trend?target={target}").json()
    assert [p["scan_id"] for p in alice_trend["points"]] == [a.json()["scan_id"]]
    assert [p["scan_id"] for p in bob_trend["points"]] == [b.json()["scan_id"]]


def test_schedules_are_scoped_per_visitor(alice, bob):
    created = alice.post("/api/schedules", json={
        "target": "https://example.com", "interval_minutes": 60, "modules": ["web"], "authorized": True,
    })
    sid = created.json()["id"]

    assert bob.get("/api/schedules").json() == []
    assert any(s["id"] == sid for s in alice.get("/api/schedules").json())

    # Bob can't disable or delete Alice's schedule.
    assert bob.patch(f"/api/schedules/{sid}", json={"enabled": False}).status_code == 404
    assert bob.delete(f"/api/schedules/{sid}").status_code == 404

    # Alice still can.
    assert alice.delete(f"/api/schedules/{sid}").json()["action"] == "deleted"
