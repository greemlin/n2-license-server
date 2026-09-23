"""SQLAlchemy database setup."""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import Settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _migrate_sqlite(engine: Engine) -> None:
    """Add any columns that exist in models but not yet in the SQLite DB."""
    from sqlalchemy import Column, inspect, text

    inspector = inspect(engine)
    for table in Base.metadata.tables.values():
        table_name = table.name
        existing_cols = {c["name"] for c in inspector.get_columns(table_name)} if inspector.has_table(table_name) else set()
        for col in table.columns:
            if col.name not in existing_cols:
                with engine.begin() as conn:
                    conn.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {col.name} {col.type}")
                    )


def init_engine(settings: Settings) -> None:
    global _engine, _SessionLocal
    connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    _engine = create_engine(
        settings.database_url,
        echo=settings.debug,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    Base.metadata.create_all(_engine)
    if settings.database_url.startswith("sqlite"):
        _migrate_sqlite(_engine)
    _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def get_engine() -> Engine:
    if _engine is None:
        raise RuntimeError("Database engine not initialized")
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        raise RuntimeError("Database session factory not initialized")
    return _SessionLocal


def SessionLocal() -> Session:
    return get_session_factory()()
