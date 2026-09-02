"""Anonymous per-visitor scoping — no accounts, no login.

Each browser gets a random, unguessable id the first time it calls the API,
stored as an httpOnly cookie. Every scan/schedule row is tagged with the id of
whoever created it, and every read/write is filtered by it — so two visitors
sharing the same public deployment never see each other's scan history, even
though neither ever signs in.

This is NOT an authentication system: it doesn't prove who a visitor is, it
only keeps one visitor's data apart from another's. Clearing cookies or
switching browsers starts a fresh, empty history — same trade-off as any
"guest cart" style session.
"""
from __future__ import annotations

import uuid

from fastapi import Request, Response

from api.config import get_settings

OWNER_COOKIE_NAME = "vantis_sid"
_ONE_YEAR_SECONDS = 60 * 60 * 24 * 365


def get_owner_id(request: Request, response: Response) -> str:
    """FastAPI dependency: returns the caller's anonymous owner id, minting and
    setting the cookie on first visit. Depend on this (not read the cookie
    directly) in every route that creates or lists user-owned rows."""
    owner_id = request.cookies.get(OWNER_COOKIE_NAME)
    if not owner_id:
        owner_id = uuid.uuid4().hex
        response.set_cookie(
            OWNER_COOKIE_NAME, owner_id,
            max_age=_ONE_YEAR_SECONDS,
            httponly=True, samesite="lax", secure=get_settings().cookie_secure,
        )
    return owner_id


def owner_id_from_websocket_cookies(cookies: dict) -> str | None:
    """Same lookup for the WebSocket handshake (Starlette exposes handshake
    cookies as a plain dict, not the cookie-jar helper Request has)."""
    return cookies.get(OWNER_COOKIE_NAME)
