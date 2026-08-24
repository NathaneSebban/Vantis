"""Runtime configuration, sourced from environment variables.

Everything an operator might tune when deploying the API lives here so no
secret or environment-specific value is hard-coded. Uses pydantic-settings so
values come from the environment (or a local .env) with sane defaults for
running on a laptop.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VANTIS_", env_file=".env", extra="ignore")

    # Persistence — a single SQLite file by default; swap for Postgres in prod.
    database_url: str = "sqlite:///./vantis.db"

    # CORS — comma-separated list of allowed origins. Deliberately NOT "*":
    # the frontend origin must be declared explicitly so the API is safe to
    # expose. Defaults cover the Vite dev server.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Rate limiting on scan creation, to blunt abuse if exposed publicly.
    scan_rate_limit: str = "5/hour"

    # --- Optional hardening (all OFF by default: local dev is unaffected) ---

    # API key. When set (non-empty), every /api/scans request must present it
    # via the X-API-Key header (or ?key= for the WebSocket). Leave empty to
    # disable auth. SET THIS before exposing the API beyond localhost.
    api_key: str = ""

    # When true, reject targets that resolve to a literal private, loopback,
    # link-local or reserved IP (basic anti-SSRF). OFF by default because
    # authorized internal pentests legitimately target internal hosts.
    block_private_targets: bool = False

    # Scan engine defaults (mirrors the CLI defaults).
    http_timeout: float = 10.0
    rate_limit_delay: float = 0.3

    # How many scans may run concurrently in the in-memory worker pool.
    max_concurrent_scans: int = 2

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
