"""
Argus ASM — database setup
Provides:
  engine    — SQLAlchemy engine (use for migrations / init)
  get_db()  — context manager that yields a session and handles
              commit/rollback/close automatically
  init_db() — creates all tables if they don't exist yet
"""

from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from .models import Base
from config.settings import settings


# Create the engine once at module load time
engine = create_engine(
    settings.DATABASE_URL,
    # Connection pool settings suitable for a single-process scan tool
    pool_pre_ping=True,         # test connections before use
    pool_size=5,
    max_overflow=10,
    echo=settings.DB_ECHO,      # set True in .env to log all SQL
)

# Session factory — don't use directly; use get_db() instead
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


def init_db() -> None:
    """
    Create all tables defined in models.py if they don't already exist.
    Safe to call on every startup — won't drop existing data.
    """
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db() -> Session:
    """
    Yield a database session, committing on success and rolling back
    on any exception.

    Usage:
        from db import get_db

        with get_db() as db:
            db.add(some_model_instance)
            # commit happens automatically on exit
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
