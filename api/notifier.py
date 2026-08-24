"""
Outbound webhook notifications.

When a scan finishes with findings at or above a configured severity, POST a
compact summary to a webhook URL (Slack/Discord/any endpoint accept the `text`
field). Disabled by default (empty VANTIS_WEBHOOK_URL). Best-effort: a failing
webhook never affects the scan.
"""
from __future__ import annotations

import requests

from api.config import get_settings

_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def _at_or_above(counts: dict[str, int], minimum: str) -> int:
    try:
        floor = _SEV_ORDER.index(minimum)
    except ValueError:
        floor = _SEV_ORDER.index("high")
    return sum(counts.get(s, 0) for s in _SEV_ORDER[floor:])


def build_payload(target: str, scan_id: str, counts: dict[str, int], minimum: str) -> dict | None:
    """Return the webhook JSON body, or None if nothing meets the threshold."""
    n = _at_or_above(counts, minimum)
    if n <= 0:
        return None
    parts = [f"{counts.get(s, 0)} {s}" for s in reversed(_SEV_ORDER) if counts.get(s, 0)]
    summary = ", ".join(parts) or "no findings"
    text = (f":rotating_light: Vantis scan of {target} finished with {n} finding(s) "
            f"at/above {minimum}. Breakdown: {summary}. (scan {scan_id})")
    return {"text": text, "target": target, "scan_id": scan_id,
            "counts": counts, "at_or_above": n, "threshold": minimum}


def notify_scan_complete(target: str, scan_id: str, counts: dict[str, int]) -> bool:
    """Send the completion webhook if configured and threshold met. Returns True
    if a request was sent (regardless of the remote's response)."""
    settings = get_settings()
    if not settings.webhook_url:
        return False
    payload = build_payload(target, scan_id, counts, settings.webhook_min_severity)
    if payload is None:
        return False
    try:
        requests.post(settings.webhook_url, json=payload, timeout=10)
        return True
    except requests.RequestException as e:
        print(f"[!] webhook notification failed: {e}")
        return False
