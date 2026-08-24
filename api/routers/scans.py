"""/api/scans routes: create, inspect, stream, export and manage scans."""
from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.database import get_db
from api.models import FindingRow, ScanRow, ScanStatus
from api.rate_limit import limiter
from api.config import get_settings
from api.scan_runner import scan_manager
from api.security import require_api_key, websocket_authorized
from api.schemas import (
    FindingOut,
    ScanCreate,
    ScanCreatedResponse,
    ScanDetail,
    ScanListResponse,
    ScanSummary,
    SeverityCounts,
)
from api.websocket_manager import ws_manager
from vantis.core.report import Finding, Report, Severity

router = APIRouter(prefix="/api/scans", tags=["scans"])

_SEVERITIES = ["critical", "high", "medium", "low", "info"]


# -- helpers ----------------------------------------------------------

def _severity_counts(db: Session, scan_id: str) -> SeverityCounts:
    rows = db.execute(
        select(FindingRow.severity, func.count())
        .where(FindingRow.scan_id == scan_id)
        .group_by(FindingRow.severity)
    ).all()
    counts = {sev: 0 for sev in _SEVERITIES}
    for severity, n in rows:
        if severity in counts:
            counts[severity] = n
    return SeverityCounts(**counts)


def _summary(db: Session, scan: ScanRow) -> ScanSummary:
    counts = _severity_counts(db, scan.id)
    return ScanSummary(
        scan_id=scan.id,
        target=scan.target,
        scope=scan.scope_list,
        modules=scan.modules_list,
        status=scan.status,
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        findings_count=sum(counts.model_dump().values()),
        severity_counts=counts,
    )


def _get_scan_or_404(db: Session, scan_id: str) -> ScanRow:
    scan = db.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


# -- routes -----------------------------------------------------------

@router.post("", response_model=ScanCreatedResponse, status_code=202, dependencies=[Depends(require_api_key)])
@limiter.limit(get_settings().scan_rate_limit)
def create_scan(request: Request, payload: ScanCreate, db: Session = Depends(get_db)) -> ScanCreatedResponse:
    """Queue a scan. The ``authorized`` flag is the web equivalent of the
    CLI's interactive authorization gate — false/absent is a hard 400."""
    if not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail=(
                "Authorization required: set 'authorized': true to confirm you are "
                "permitted to test this target. Unauthorized scanning is illegal."
            ),
        )

    scan_id = str(uuid.uuid4())
    scan = ScanRow(
        id=scan_id,
        target=payload.target,
        scope=",".join(payload.scope),
        modules=",".join(payload.modules),
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()

    # headers/cookies are handed to the runner in-memory only — never stored.
    scan_manager.submit(
        scan_id, payload.target, payload.scope, payload.modules,
        auth_headers=payload.headers or None, auth_cookies=payload.cookies or None,
    )
    return ScanCreatedResponse(scan_id=scan_id, status=ScanStatus.QUEUED)


@router.get("", response_model=ScanListResponse, dependencies=[Depends(require_api_key)])
def list_scans(
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> ScanListResponse:
    total = db.scalar(select(func.count()).select_from(ScanRow)) or 0
    scans = db.scalars(
        select(ScanRow).order_by(ScanRow.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return ScanListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[_summary(db, s) for s in scans],
    )


@router.get("/{scan_id}", response_model=ScanDetail, dependencies=[Depends(require_api_key)])
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanDetail:
    scan = _get_scan_or_404(db, scan_id)
    summary = _summary(db, scan)
    return ScanDetail(
        **summary.model_dump(),
        current_module=scan.current_module,
        modules_done=scan.modules_done,
        modules_total=scan.modules_total,
        error=scan.error,
    )


@router.get("/{scan_id}/findings", response_model=list[FindingOut], dependencies=[Depends(require_api_key)])
def get_findings(
    scan_id: str,
    db: Session = Depends(get_db),
    severity: str | None = Query(None, description="Comma-separated: e.g. high,critical"),
    module: str | None = Query(None, description="Comma-separated module names: e.g. reflected-xss"),
) -> list[FindingOut]:
    _get_scan_or_404(db, scan_id)
    stmt = select(FindingRow).where(FindingRow.scan_id == scan_id)

    if severity:
        wanted = [s.strip().lower() for s in severity.split(",") if s.strip()]
        if wanted:
            stmt = stmt.where(FindingRow.severity.in_(wanted))
    if module:
        wanted = [m.strip().lower() for m in module.split(",") if m.strip()]
        if wanted:
            stmt = stmt.where(FindingRow.module.in_(wanted))

    rows = db.scalars(stmt).all()
    # Sort by severity weight, highest first — same order the report uses.
    rows.sort(key=lambda r: Severity(r.severity).weight if r.severity in Severity._value2member_map_ else -1, reverse=True)
    return [FindingOut(**r.to_dict()) for r in rows]


@router.get("/{scan_id}/report", dependencies=[Depends(require_api_key)])
def get_report(
    scan_id: str,
    db: Session = Depends(get_db),
    format: str = Query("json", pattern="^(json|html|md|pdf)$"),
) -> Response:
    """Rebuild a library Report from persisted findings and reuse the existing
    exporters so downloads match exactly what the CLI produces."""
    scan = _get_scan_or_404(db, scan_id)

    report = Report(target=scan.target)
    if scan.started_at:
        report.started_at = scan.started_at.isoformat()
    for r in db.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all():
        d = r.to_dict()
        report.add(Finding(
            module=d["module"], title=d["title"], severity=Severity(d["severity"]),
            target=d["target"], description=d["description"], evidence=d["evidence"],
            remediation=d["remediation"], references=d["references"],
            matched_at=d["matched_at"], timestamp=d["timestamp"],
        ))

    ext, media = {"json": ("json", "application/json"),
                  "html": ("html", "text/html"),
                  "md": ("md", "text/markdown"),
                  "pdf": ("pdf", "application/pdf")}[format]

    # PDF is binary; the others are text. Create the temp file accordingly.
    binary = format == "pdf"
    mode = "wb" if binary else "w+"
    kwargs = {} if binary else {"encoding": "utf-8"}
    with tempfile.NamedTemporaryFile(mode, suffix=f".{ext}", delete=False, **kwargs) as tmp:
        tmp_path = Path(tmp.name)
    try:
        if format == "json":
            report.to_json(tmp_path)
        elif format == "html":
            report.to_html(tmp_path)
        elif format == "pdf":
            report.to_pdf(tmp_path)
        else:
            report.to_markdown(tmp_path)
        content = tmp_path.read_bytes()
    finally:
        tmp_path.unlink(missing_ok=True)

    filename = f"vantis-{scan_id[:8]}.{ext}"
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/{scan_id}", status_code=200, dependencies=[Depends(require_api_key)])
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> dict:
    """Cancel a running scan if possible; otherwise delete its history."""
    scan = _get_scan_or_404(db, scan_id)

    if scan.status in {ScanStatus.QUEUED, ScanStatus.RUNNING} and scan_manager.request_cancel(scan_id):
        return {"scan_id": scan_id, "action": "cancellation_requested"}

    db.delete(scan)  # findings cascade
    db.commit()
    return {"scan_id": scan_id, "action": "deleted"}


@router.websocket("/{scan_id}/live")
async def scan_live(websocket: WebSocket, scan_id: str) -> None:
    """Stream scan events (status changes, findings, module progress) live.

    The socket stays open until the client disconnects; the scan thread pushes
    events through the WebSocketManager."""
    # Auth (when enabled) happens before accept() — an unauthorized handshake is
    # closed without ever joining the broadcast set.
    if not await websocket_authorized(websocket):
        return
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            # We don't expect client messages, but awaiting receive() is how we
            # detect disconnects and keep the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
    except Exception:  # noqa: BLE001
        ws_manager.disconnect(scan_id, websocket)
