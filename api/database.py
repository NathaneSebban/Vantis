"""SQLAlchemy engine / session wiring.

Kept intentionally small: one engine, one session factory, one declarative
base, and a FastAPI dependency that yields a session and always closes it.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from api.config import get_settings

settings = get_settings()

# check_same_thread=False: scans run in worker threads and need DB access from
# a thread other than the one that created the connection. Only relevant to
# SQLite; ignored for other backends.
_connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yields a session, guarantees it is closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
