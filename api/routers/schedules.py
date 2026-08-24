"""/api/schedules routes: manage recurring scans."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.database import get_db
from api.models import ScheduleRow, _utcnow
from api.security import require_api_key
from api.schemas import ScheduleCreate, ScheduleOut, ScheduleUpdate

router = APIRouter(prefix="/api/schedules", tags=["schedules"], dependencies=[Depends(require_api_key)])


def _out(s: ScheduleRow) -> ScheduleOut:
    return ScheduleOut(
        id=s.id, target=s.target, scope=s.scope_list, modules=s.modules_list,
        interval_minutes=s.interval_minutes, enabled=s.enabled, created_at=s.created_at,
        next_run_at=s.next_run_at, last_run_at=s.last_run_at, last_scan_id=s.last_scan_id,
    )


@router.post("", response_model=ScheduleOut, status_code=201)
def create_schedule(payload: ScheduleCreate, db: Session = Depends(get_db)) -> ScheduleOut:
    if not payload.authorized:
        raise HTTPException(status_code=400,
                            detail="Authorization required: set 'authorized': true to schedule recurring scans.")
    sched = ScheduleRow(
        id=str(uuid.uuid4()), target=payload.target, scope=",".join(payload.scope),
        modules=",".join(payload.modules), interval_minutes=payload.interval_minutes,
        enabled=True, authorized=True, next_run_at=_utcnow(),
    )
    db.add(sched)
    db.commit()
    return _out(sched)


@router.get("", response_model=list[ScheduleOut])
def list_schedules(db: Session = Depends(get_db)) -> list[ScheduleOut]:
    rows = db.scalars(select(ScheduleRow).order_by(ScheduleRow.created_at.desc())).all()
    return [_out(s) for s in rows]


@router.patch("/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: str, payload: ScheduleUpdate, db: Session = Depends(get_db)) -> ScheduleOut:
    sched = db.get(ScheduleRow, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    sched.enabled = payload.enabled
    db.commit()
    return _out(sched)


@router.delete("/{schedule_id}", status_code=200)
def delete_schedule(schedule_id: str, db: Session = Depends(get_db)) -> dict:
    sched = db.get(ScheduleRow, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="schedule not found")
    db.delete(sched)
    db.commit()
    return {"schedule_id": schedule_id, "action": "deleted"}
