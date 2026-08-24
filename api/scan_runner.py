"""Background scan execution.

Adapts the synchronous :class:`vantis.core.engine.Engine` to run off the
request path. A small in-memory :class:`ScanManager` owns a thread pool and a
registry of live jobs; each job drives the engine with a progress callback
that (1) persists findings, (2) updates the scan's progress in the DB, (3)
supports cooperative cancellation, and (4) streams events to WebSocket
subscribers.

Everything crosses exactly one boundary — the worker thread hands events back
to the event loop via ``run_coroutine_threadsafe`` — so it is deliberately
structured to be swapped for Celery/RQ later: replace ``submit`` with an
enqueue and ``_run_job`` becomes the task body, untouched.
"""
from __future__ import annotations

import asyncio
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Optional

from api.config import get_settings
from api.database import SessionLocal
from api.models import FindingRow, ScanRow, ScanStatus
from api.websocket_manager import ws_manager
from vantis.core.engine import Engine, ScanControlSignal
from vantis.core.report import Finding
from vantis.core.target import Target


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _finding_to_row(scan_id: str, f: Finding) -> FindingRow:
    d = f.to_dict()
    return FindingRow(
        scan_id=scan_id,
        module=d["module"],
        title=d["title"],
        severity=d["severity"],
        target=d["target"],
        description=d["description"],
        evidence=d["evidence"],
        remediation=d["remediation"],
        refs="\n".join(d.get("references") or []),
        matched_at=d["matched_at"],
        timestamp=d["timestamp"],
    )


class ScanManager:
    def __init__(self) -> None:
        self._executor: Optional[ThreadPoolExecutor] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._cancel_flags: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Called at app startup: records the event loop worker threads post
        WebSocket events to, and (re)creates a fresh thread pool so the manager
        survives an app restart within the same process (e.g. across tests)."""
        self._loop = loop
        settings = get_settings()
        self._executor = ThreadPoolExecutor(
            max_workers=settings.max_concurrent_scans, thread_name_prefix="vantis-scan"
        )

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    # -- submission ---------------------------------------------------

    def submit(self, scan_id: str, target: str, scope: list[str], modules: list[str]) -> None:
        if self._executor is None:
            raise RuntimeError("ScanManager not started: bind_loop() was never called")
        with self._lock:
            self._cancel_flags[scan_id] = threading.Event()
        self._executor.submit(self._run_job, scan_id, target, scope, modules)

    def request_cancel(self, scan_id: str) -> bool:
        """Signal a running job to stop at the next module boundary.

        Returns True if a live job was signalled, False if there was nothing
        running to cancel."""
        with self._lock:
            flag = self._cancel_flags.get(scan_id)
        if flag is None:
            return False
        flag.set()
        return True

    def is_running(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._cancel_flags

    # -- WebSocket bridge ---------------------------------------------

    def _push_ws(self, scan_id: str, message: dict[str, Any]) -> None:
        """Schedule a WebSocket broadcast on the event loop from a worker
        thread. Best-effort: streaming failures never affect the scan."""
        if self._loop is None or not self._loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(ws_manager.broadcast(scan_id, message), self._loop)
        except Exception:  # noqa: BLE001
            pass

    # -- the job body -------------------------------------------------

    def _run_job(self, scan_id: str, target: str, scope: list[str], modules: list[str]) -> None:
        settings = get_settings()
        db = SessionLocal()
        cancel_flag = self._cancel_flags.get(scan_id)

        def safe_commit() -> bool:
            """Commit, rolling back on failure so the session stays usable.

            The engine swallows non-cancellation exceptions raised by this
            callback (to protect scans from broken observers), which would
            otherwise leave a failed commit's session in a broken state and
            cascade into every later write. Handling the error here keeps the
            session healthy and makes a lost write visible in the logs rather
            than silent."""
            try:
                db.commit()
                return True
            except Exception as e:  # noqa: BLE001 - persistence hiccup (e.g. lock)
                db.rollback()
                print(f"[!] scan {scan_id}: DB commit failed, rolled back: {e}")
                return False

        def progress(event: str, payload: dict) -> None:
            # Cooperative cancellation: checked at each module boundary.
            if cancel_flag is not None and cancel_flag.is_set() and event == "module_start":
                raise ScanControlSignal()

            if event == "module_start":
                scan = db.get(ScanRow, scan_id)
                if scan:
                    scan.current_module = payload["module"]
                    scan.modules_total = payload["total"]
                    safe_commit()
                self._push_ws(scan_id, {"type": "module_start", **_public(payload)})

            elif event == "finding":
                f: Finding = payload["finding"]
                db.add(_finding_to_row(scan_id, f))
                if safe_commit():
                    self._push_ws(scan_id, {"type": "finding", "finding": f.to_dict()})

            elif event == "module_end":
                scan = db.get(ScanRow, scan_id)
                if scan:
                    scan.modules_done = payload["index"]
                    safe_commit()
                self._push_ws(scan_id, {"type": "module_end", **_public(payload)})

            elif event == "scan_end":
                self._push_ws(scan_id, {"type": "scan_end", **payload})

        try:
            scan = db.get(ScanRow, scan_id)
            if scan is None:
                return
            scan.status = ScanStatus.RUNNING
            scan.started_at = _utcnow()
            db.commit()
            self._push_ws(scan_id, {"type": "status", "status": ScanStatus.RUNNING})

            engine = Engine(
                target=Target(raw=target, scope=scope or []),
                categories=modules,
                http_timeout=settings.http_timeout,
                rate_limit_delay=settings.rate_limit_delay,
            )
            engine.run(progress_callback=progress)

            scan = db.get(ScanRow, scan_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.current_module = ""
                scan.finished_at = _utcnow()
                db.commit()
            self._push_ws(scan_id, {"type": "status", "status": ScanStatus.COMPLETED})

        except ScanControlSignal:
            db.rollback()
            scan = db.get(ScanRow, scan_id)
            if scan:
                scan.status = ScanStatus.CANCELLED
                scan.current_module = ""
                scan.finished_at = _utcnow()
                db.commit()
            self._push_ws(scan_id, {"type": "status", "status": ScanStatus.CANCELLED})

        except Exception as e:  # noqa: BLE001 - record failure, never crash the pool
            traceback.print_exc()
            db.rollback()
            scan = db.get(ScanRow, scan_id)
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error = str(e)
                scan.finished_at = _utcnow()
                db.commit()
            self._push_ws(scan_id, {"type": "status", "status": ScanStatus.FAILED, "error": str(e)})

        finally:
            db.close()
            with self._lock:
                self._cancel_flags.pop(scan_id, None)


def _public(payload: dict) -> dict:
    """Strip non-serializable internals before sending a payload over WS."""
    return {k: v for k, v in payload.items() if k != "finding"}


scan_manager = ScanManager()
