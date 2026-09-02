"""
Recurring-scan scheduler.

A single background thread wakes periodically and launches any schedule whose
next_run_at is due, then advances it. The due-checking logic lives in `tick()`
so it can be unit-tested without waiting on the clock. Each launched scan goes
through the same ScanManager as manual scans.

Only schedules created with authorization (authorized=True) are ever run — the
web-equivalent of confirming the authorization gate for all future runs.
"""
from __future__ import annotations

import threading
import uuid
from datetime import timedelta

from sqlalchemy import select

from api.database import SessionLocal
from api.models import ScanRow, ScanStatus, ScheduleRow, _utcnow
from api.scan_runner import scan_manager


class Scheduler:
    def __init__(self, check_interval: float = 30.0) -> None:
        self.check_interval = check_interval
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="vantis-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.wait(self.check_interval):
            try:
                self.tick()
            except Exception as e:  # noqa: BLE001 - a bad tick must not kill the loop
                print(f"[!] scheduler tick error: {e}")

    def tick(self) -> list[str]:
        """Launch all due, enabled, authorized schedules. Returns the scan ids
        started. Safe to call directly (used by tests)."""
        started: list[str] = []
        db = SessionLocal()
        try:
            now = _utcnow()
            due = db.scalars(select(ScheduleRow).where(
                ScheduleRow.enabled.is_(True),
                ScheduleRow.authorized.is_(True),
                ScheduleRow.next_run_at <= now,
            )).all()
            for sched in due:
                scan_id = str(uuid.uuid4())
                db.add(ScanRow(
                    id=scan_id, target=sched.target, owner_id=sched.owner_id, scope=sched.scope,
                    modules=sched.modules, status=ScanStatus.QUEUED,
                ))
                sched.last_run_at = now
                sched.last_scan_id = scan_id
                sched.next_run_at = now + timedelta(minutes=sched.interval_minutes)
                db.commit()

                scan_manager.submit(scan_id, sched.target, sched.scope_list, sched.modules_list)
                started.append(scan_id)
            return started
        finally:
            db.close()


scheduler = Scheduler()
