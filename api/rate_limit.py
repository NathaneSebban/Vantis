"""Rate limiting for the API, via slowapi.

Only scan creation is limited (see the decorator in the router) — that's the
expensive, abusable endpoint. The limiter is defined here so the app and the
router share one instance.
"""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

# Keyed by client IP. Behind a proxy, configure the proxy to set a trusted
# forwarded header and adjust this key function accordingly.
limiter = Limiter(key_func=get_remote_address)
