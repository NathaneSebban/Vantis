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
    references: Mapped[str] = mapped_column(Text, default="")  # newline-separated
    matched_at: Mapped[str] = mapped_column(String(512), default="")
    timestamp: Mapped[str] = mapped_column(String(40), default="")

    scan: Mapped[ScanRow] = relationship(back_populates="findings")

    def to_dict(self) -> dict:
        """Return the same shape as the library's Finding.to_dict()."""
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": [r for r in self.references.split("\n") if r],
            "matched_at": self.matched_at,
            "timestamp": self.timestamp,
        }
