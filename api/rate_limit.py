"""Rate limiting for the API, via slowapi.

Only scan creation is limited (see the decorator in the router) — that's the
expensive, abusable endpoint. The limiter is defined here so the app and the
router share one instance.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request


def client_ip(request: Request) -> str:
    """Identify the real client, even behind the nginx reverse proxy.

    Directly using request.client.host would bucket every user behind the proxy
    under the proxy's single IP, making the per-IP limit global. Prefer the
    forwarded client IP set by the trusted proxy, falling back to the socket
    peer for direct (dev) connections.

    Note: X-Forwarded-For is only trustworthy behind a proxy that sets it (our
    nginx does, and uvicorn runs with --proxy-headers). If the API is exposed
    directly to the internet, a client could spoof this header — pair this with
    real authentication (VANTIS_API_KEY) before public exposure.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        # First entry is the original client; the rest are proxies.
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return get_remote_address(request)


limiter = Limiter(key_func=client_ip)
