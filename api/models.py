"""SQLAlchemy ORM models: scans and their findings.

The ``FindingRow`` columns mirror the library's ``Finding`` dataclass so a
persisted finding round-trips back to the exact ``Finding.to_dict()`` shape
the CLI already produces — the frontend and CLI consume one format.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    # Anonymous per-visitor id (see api/ownership.py) — no accounts, just scopes
    # a scan to whichever browser created it. Nullable: rows created before this
    # column existed have no owner and are simply invisible to every visitor.
    owner_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # scope and modules are small lists — stored as comma-separated text to
    # keep the schema portable across SQLite/Postgres without a JSON column.
    scope: Mapped[str] = mapped_column(Text, default="")
    modules: Mapped[str] = mapped_column(Text, default="")

    status: Mapped[str] = mapped_column(String(20), default=ScanStatus.QUEUED, index=True)
    current_module: Mapped[str] = mapped_column(String(120), default="")
    modules_done: Mapped[int] = mapped_column(Integer, default=0)
    modules_total: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["FindingRow"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="FindingRow.id"
    )

    @property
    def scope_list(self) -> list[str]:
        return [s for s in self.scope.split(",") if s]

    @property
    def modules_list(self) -> list[str]:
        return [m for m in self.modules.split(",") if m]


class ScheduleRow(Base):
    """A recurring scan configuration. `authorized` records the user's one-time
    authorization confirmation that covers every future run of this schedule."""
    __tablename__ = "schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    # Same anonymous per-visitor id as ScanRow.owner_id — see api/ownership.py.
    owner_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    scope: Mapped[str] = mapped_column(Text, default="")
    modules: Mapped[str] = mapped_column(Text, default="")
    interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True, index=True)
    authorized: Mapped[bool] = mapped_column(default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    next_run_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[str] = mapped_column(String(36), default="")

    @property
    def scope_list(self) -> list[str]:
        return [s for s in self.scope.split(",") if s]

    @property
    def modules_list(self) -> list[str]:
        return [m for m in self.modules.split(",") if m]


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    module: Mapped[str] = mapped_column(String(120), default="", index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="info", index=True)
    target: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    # DB column is "refs" (not "references"): "references" is a reserved SQL
    # word — avoiding it keeps the schema portable (MySQL/MariaDB/Postgres)
    # without relying on identifier quoting. The API still exposes "references".
    refs: Mapped[str] = mapped_column("refs", Text, default="")  # newline-separated
    matched_at: Mapped[str] = mapped_column(String(512), default="")
    timestamp: Mapped[str] = mapped_column(String(40), default="")
    # Triage state: open | false_positive | confirmed. Lets users suppress noise.
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    # How certain the detection is (pattern match vs statistical heuristic).
    confidence: Mapped[str] = mapped_column(String(20), default="medium")
    # Standard classification references, e.g. "A03:2021" / "CWE-89".
    owasp: Mapped[str] = mapped_column(String(20), default="")
    cwe: Mapped[str] = mapped_column(String(20), default="")

    scan: Mapped[ScanRow] = relationship(back_populates="findings")

    @property
    def identity(self) -> str:
        """Stable key for diffing across scans of the same target."""
        return f"{self.module}|{self.title}|{self.matched_at}"

    def to_dict(self) -> dict:
        """Return the same shape as the library's Finding.to_dict(), plus the
        triage status (an API-only field)."""
        return {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": [r for r in self.refs.split("\n") if r],
            "matched_at": self.matched_at,
            "timestamp": self.timestamp,
            "status": self.status,
            "confidence": self.confidence,
            "owasp": self.owasp,
            "cwe": self.cwe,
        }


class FindingStatus:
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"
    ALL = {OPEN, FALSE_POSITIVE, CONFIRMED}
