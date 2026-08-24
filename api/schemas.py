"""Pydantic request/response models.

These are the API's contract. Input validation happens here (notably the
authorization gate and target plausibility) *before* the engine is ever
touched.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

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
    # Authenticated scanning. These are used in-memory for the run only and are
    # NEVER written to the database (they are credentials).
    headers: dict[str, str] = Field(default_factory=dict, description="Extra request headers (e.g. Authorization)")
    cookies: dict[str, str] = Field(default_factory=dict, description="Session cookies")
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
