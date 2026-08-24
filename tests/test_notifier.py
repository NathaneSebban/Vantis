"""Tests for outbound webhook notifications."""
import responses

from api.config import get_settings
from api.notifier import build_payload, notify_scan_complete


def test_payload_none_below_threshold():
    # Only low/info findings, threshold high -> no notification.
    assert build_payload("http://x", "id1", {"low": 3, "info": 5}, "high") is None


def test_payload_built_at_threshold():
    p = build_payload("http://x", "id1", {"critical": 1, "high": 2, "low": 4}, "high")
    assert p is not None
    assert p["at_or_above"] == 3  # 1 critical + 2 high
    assert "critical" in p["text"] and p["target"] == "http://x"


@responses.activate
def test_notify_sends_when_configured(monkeypatch):
    monkeypatch.setattr(get_settings(), "webhook_url", "https://hooks.example/xyz")
    monkeypatch.setattr(get_settings(), "webhook_min_severity", "high")
    responses.add(responses.POST, "https://hooks.example/xyz", json={"ok": True}, status=200)

    assert notify_scan_complete("http://t", "sid", {"high": 1}) is True
    assert len(responses.calls) == 1
    assert b'"scan_id": "sid"' in responses.calls[0].request.body


def test_notify_disabled_by_default(monkeypatch):
    monkeypatch.setattr(get_settings(), "webhook_url", "")
    assert notify_scan_complete("http://t", "sid", {"critical": 5}) is False
