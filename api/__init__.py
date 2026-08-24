"""Vantis REST API — exposes the scan engine over HTTP/WebSocket.

The library under ``vantis/`` stays the single source of truth for scan
logic (``Engine``, ``ScanModule``, ``Report``). This package only adapts it
for the web: persistence, background execution, and live streaming.
"""
