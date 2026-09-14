"""Database engine and session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlmodel import Session, create_engine

from .config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
_connect_args: dict[str, bool] = {"check_same_thread": False} if _is_sqlite else {}

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    connect_args=_connect_args,
    pool_pre_ping=not _is_sqlite,
)


def prepare_database() -> None:
    """Upgrade or verify the schema before the application serves requests."""
    from .migrations import upgrade_database, verify_database_current

    if settings.DATABASE_MIGRATE_ON_STARTUP:
        upgrade_database(engine)
    else:
        verify_database_current(engine)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a SQLModel session."""
    with Session(engine) as session:
        yield session


@contextmanager
def session_scope() -> Iterator[Session]:
    """Context-manager session helper for non-request code paths."""
    with Session(engine) as session:
        yield session
