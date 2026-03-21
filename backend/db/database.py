"""
Database Layer — WeaknessIQ
============================
Security decisions:
- CWE-89:  ALL queries use SQLAlchemy ORM or parameterised statements — no raw SQL string formatting
- CWE-312: No sensitive data stored in DB
- CWE-798: Connection string from environment variable only, never hardcoded
- Async SQLite for dev; swap DATABASE_URL for PostgreSQL in production with zero code change
"""

import logging
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy import String, Text, Integer, JSON
from sqlalchemy.pool import StaticPool

logger = logging.getLogger("weaknessiq.db")

# ── Base ──────────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    pass


# ── Models ────────────────────────────────────────────────────────────────────
class CWEModel(Base):
    """
    Stores parsed CWE entries.
    JSON columns used for list fields — avoids complex joins for prototype scope.
    """
    __tablename__ = "weaknesses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cwe_id: Mapped[str] = mapped_column(String(10), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    abstraction: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    extended_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    likelihood_of_exploit: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    detection_methods: Mapped[list] = mapped_column(JSON, default=list)
    common_consequences: Mapped[list] = mapped_column(JSON, default=list)
    related_weaknesses: Mapped[list] = mapped_column(JSON, default=list)
    applicable_platforms: Mapped[list] = mapped_column(JSON, default=list)
    affected_resources: Mapped[list] = mapped_column(JSON, default=list)


# ── Engine factory ────────────────────────────────────────────────────────────
_engine = None
_session_factory = None


def get_db_url() -> str:
    """
    Read DB URL from environment — CWE-798: never hardcode credentials.
    Defaults to local SQLite for development.
    """
    import os
    return os.getenv(
        "DATABASE_URL",
        f"sqlite+aiosqlite:///{Path(__file__).parent.parent.parent}/data/weaknessiq.db"
    )


def init_engine():
    global _engine, _session_factory
    db_url = get_db_url()
    logger.info(f"Initialising DB engine: {db_url.split('///')[0]}///***")  # Never log full path

    connect_args = {}
    if "sqlite" in db_url:
        connect_args["check_same_thread"] = False

    _engine = create_async_engine(
        db_url,
        connect_args=connect_args,
        poolclass=StaticPool if "sqlite" in db_url else None,
        echo=False,   # Never True in production — logs all SQL including data
    )
    _session_factory = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


async def create_tables():
    """Create all tables if they don't exist."""
    engine = _engine or init_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")


async def get_session() -> AsyncSession:
    """FastAPI dependency — yields a DB session per request."""
    if _session_factory is None:
        init_engine()
    async with _session_factory() as session:
        yield session
