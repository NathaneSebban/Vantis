"""Tracks live WebSocket subscribers per scan and fans out messages to them.

Scans run in worker threads, so the manager is called from two worlds: the
async request handlers register/unregister sockets, while the scan thread
publishes events via :meth:`ScanManager` using ``run_coroutine_threadsafe``.
All the shared-state mutation here happens on the event loop, keeping it
single-threaded and lock-free.
"""
from __future__ import annotations

from collections import defaultdict

from fastapi import WebSocket


class WebSocketManager:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[scan_id].add(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        conns = self._connections.get(scan_id)
        if not conns:
            return
        conns.discard(websocket)
        if not conns:
            self._connections.pop(scan_id, None)

    def has_listeners(self, scan_id: str) -> bool:
        return bool(self._connections.get(scan_id))

    async def broadcast(self, scan_id: str, message: dict) -> None:
        """Send a JSON message to every socket subscribed to this scan.

        Dead sockets are pruned rather than allowed to raise — a viewer who
        closed their tab must never disrupt a running scan."""
        dead: list[WebSocket] = []
        for ws in list(self._connections.get(scan_id, ())):
            try:
                await ws.send_json(message)
            except Exception:  # noqa: BLE001 - connection went away mid-send
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


ws_manager = WebSocketManager()
