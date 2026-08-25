"""Pydantic request/response models.

These are the API's contract. Input validation happens here (notably the
authorization gate and target plausibility) *before* the engine is ever
touched.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field, field_serializer, field_validator


def _as_utc(v: Optional[datetime]) -> Optional[datetime]:
    """Timestamps are stored as naive UTC (the DB strips tzinfo). Tag them as
    UTC on the way out so clients (e.g. `new Date(...)` in the browser) convert
    to the viewer's local time instead of treating UTC as local."""
    if v is not None and v.tzinfo is None:
        return v.replace(tzinfo=timezone.utc)
    return v

from api.config import get_settings
from vantis.core.target import Target

VALID_CATEGORIES = {"recon", "web", "cve"}

_LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _host_is_private(host: str) -> bool:
    """True if the host is a literal private/loopback/link-local/reserved IP or
    an obvious localhost name. Hostnames are not DNS-resolved here — this is a
    coarse literal-IP guard, not a full anti-SSRF resolver."""
    if host.lower() in _LOCALHOST_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


class ScanCreate(BaseModel):
    target: str = Field(..., description="Target URL, domain or IP, e.g. https://example.com")
    scope: list[str] = Field(default_factory=list, description="Additional in-scope hosts/domains/CIDRs")
    modules: list[str] = Field(default_factory=lambda: ["recon", "web", "cve"])
    # Optional: specific module names to run (e.g. ["tls-audit", "cors-misconfig"]).
    # When provided, overrides the category selection with an exact module set.
    module_names: list[str] = Field(default_factory=list)
    # Render the target in headless Chromium to discover JS-rendered content
    # and real XHR/fetch API calls. Slower; off by default.
    browser_crawl: bool = False
    # Authenticated scanning. These are used in-memory for the run only and are
    # NEVER written to the database (they are credentials).
    headers: dict[str, str] = Field(default_factory=dict, description="Extra request headers (e.g. Authorization)")
    cookies: dict[str, str] = Field(default_factory=dict, description="Session cookies")
    # A second authenticated identity, for IDOR testing (idor-check compares
    # what this identity can access against the primary identity's resources).
    secondary_headers: dict[str, str] = Field(default_factory=dict)
    secondary_cookies: dict[str, str] = Field(default_factory=dict)
    authorized: bool = Field(
        ...,
        description=(
            "Explicit authorization confirmation. Replaces the CLI's interactive "
            "prompt. Must be true — the scan is refused otherwise."
        ),
    )

    @field_validator("target")
    @classmethod
    def _validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        # Reuse the library's own validation so the API and CLI agree on what
        # a plausible target is — rejected here, before any scan is scheduled.
        try:
            target = Target(raw=v)
        except ValueError as e:
            raise ValueError(str(e)) from e
        # Optional anti-SSRF guard (off by default).
        if get_settings().block_private_targets and _host_is_private(target.host):
            raise ValueError(
                "target resolves to a private/loopback/reserved address, which is "
                "blocked by this server's policy (VANTIS_BLOCK_PRIVATE_TARGETS)"
            )
        return v

    @field_validator("modules")
    @classmethod
    def _validate_modules(cls, v: list[str]) -> list[str]:
        cleaned = [m.strip().lower() for m in v if m.strip()]
        if not cleaned:
            raise ValueError("at least one module category is required")
        unknown = [m for m in cleaned if m not in VALID_CATEGORIES]
        if unknown:
            raise ValueError(f"unknown module categories: {', '.join(unknown)} (allowed: recon, web, cve)")
        return cleaned


class ScanCreatedResponse(BaseModel):
    scan_id: str
    status: str


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummary(BaseModel):
    """Compact scan record for the history list."""
    scan_id: str
    target: str
    scope: list[str]
    modules: list[str]
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    findings_count: int = 0
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)

    @field_serializer("created_at", "started_at", "finished_at")
    def _ser_utc(self, v: Optional[datetime]) -> Optional[datetime]:
        return _as_utc(v)


class ScanDetail(ScanSummary):
    """Full status, including live progress while running."""
    current_module: str = ""
    modules_done: int = 0
    modules_total: int = 0
    error: str = ""


class ScanListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ScanSummary]


class FindingOut(BaseModel):
    id: Optional[int] = None
    module: str
    title: str
    severity: str
    target: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    matched_at: str = ""
    timestamp: str = ""
    status: str = "open"


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., description="open | false_positive | confirmed")

    @field_validator("status")
    @classmethod
    def _valid(cls, v: str) -> str:
        allowed = {"open", "false_positive", "confirmed"}
        if v not in allowed:
            raise ValueError(f"status must be one of: {', '.join(sorted(allowed))}")
        return v


class ScheduleCreate(BaseModel):
    target: str
    scope: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=lambda: ["recon", "web", "cve"])
    interval_minutes: int = Field(..., ge=5, description="Minimum 5 minutes")
    authorized: bool = Field(..., description="Authorization covering every future run")

    @field_validator("target")
    @classmethod
    def _v_target(cls, v: str) -> str:
        v = v.strip()
        try:
            target = Target(raw=v)
        except ValueError as e:
            raise ValueError(str(e)) from e
        if get_settings().block_private_targets and _host_is_private(target.host):
            raise ValueError("target blocked by private-address policy")
        return v

    @field_validator("modules")
    @classmethod
    def _v_modules(cls, v: list[str]) -> list[str]:
        cleaned = [m.strip().lower() for m in v if m.strip()]
        unknown = [m for m in cleaned if m not in VALID_CATEGORIES]
        if not cleaned or unknown:
            raise ValueError("invalid module categories")
        return cleaned


class ScheduleOut(BaseModel):
    id: str
    target: str
    scope: list[str]
    modules: list[str]
    interval_minutes: int
    enabled: bool
    created_at: datetime
    next_run_at: datetime
    last_run_at: Optional[datetime] = None
    last_scan_id: str = ""

    @field_serializer("created_at", "next_run_at", "last_run_at")
    def _ser_utc(self, v: Optional[datetime]) -> Optional[datetime]:
        return _as_utc(v)


class ScheduleUpdate(BaseModel):
    enabled: bool


class ScanDiff(BaseModel):
    base_scan_id: str
    against_scan_id: str
    new: list[FindingOut] = Field(default_factory=list)       # in base, not in against
    fixed: list[FindingOut] = Field(default_factory=list)     # in against, not in base
    unchanged_count: int = 0
