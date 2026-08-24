"""FastAPI application: mounts routers, wires CORS, rate limiting and the
background scan manager's lifecycle.

Run locally with:  uvicorn api.main:app --reload
Interactive docs:  http://localhost:8000/docs
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from api.config import get_settings
from api.database import Base, engine
from api.rate_limit import limiter
from api.routers import scans, schedules
from api.scan_runner import scan_manager
from api.scheduler import scheduler

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables if they don't exist. Alembic owns schema migrations, but
    # this keeps the app runnable out-of-the-box (tests, `docker compose up`)
    # without a manual migration step for a fresh SQLite file.
    Base.metadata.create_all(bind=engine)
    # Hand the running event loop to the scan manager so worker threads can
    # push WebSocket events back onto it.
    scan_manager.bind_loop(asyncio.get_running_loop())
    scheduler.start()
    try:
        yield
    finally:
        scheduler.stop()
        scan_manager.shutdown()


app = FastAPI(
    title="Vantis API",
    version="0.1.0",
    description=(
        "REST API around the Vantis modular vulnerability scanner. "
        "For AUTHORIZED security testing only — every scan requires explicit "
        "authorization (`authorized: true`)."
    ),
    lifespan=lifespan,
)

# Rate limiting (slowapi).
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — explicit origins only, never "*", so credentials-bearing requests
# from the known frontend are allowed and nothing else.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(schedules.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {"status": "ok", "service": "vantis-api", "version": "0.1.0"}
