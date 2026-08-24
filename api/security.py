"""Optional API-key authentication.

Disabled by default (empty VANTIS_API_KEY) so local development and the test
suite need no credentials. When a key is configured, REST requests must send it
in the ``X-API-Key`` header; the WebSocket — which browsers cannot send custom
headers on — accepts it as a ``?key=`` query parameter instead.
"""
from __future__ import annotations

from fastapi import Header, HTTPException, WebSocket, status

from api.config import get_settings


def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """FastAPI dependency for REST routes. No-op when auth is disabled."""
    api_key = get_settings().api_key
    if not api_key:
        return
    if not x_api_key or x_api_key != api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )


async def websocket_authorized(websocket: WebSocket) -> bool:
    """Authorize a WebSocket handshake. Closes the socket and returns False when
    a configured key is missing/incorrect; returns True when auth is disabled."""
    api_key = get_settings().api_key
    if not api_key:
        return True
    if websocket.query_params.get("key") != api_key:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False
    return True
