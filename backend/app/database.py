"""SQLite engine and session factory."""

from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

_state: dict[str, object] = {"engine": None, "url": None, "factory": None}


def _enable_sqlite(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


def get_engine():
    url = get_settings().sqlalchemy_url
    engine = _state["engine"]
    if engine is not None and _state["url"] == url:
        return engine
    if engine is not None:
        engine.dispose()
    engine = create_engine(url, connect_args={"check_same_thread": False}, future=True)
    event.listen(engine, "connect", _enable_sqlite)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    _state["engine"] = engine
    _state["url"] = url
    _state["factory"] = factory
    return engine


def SessionLocal() -> Session:
    get_engine()
    factory = _state["factory"]
    return factory()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def reset_database_state() -> None:
    engine = _state["engine"]
    if engine is not None:
        engine.dispose()
    _state["engine"] = None
    _state["url"] = None
    _state["factory"] = None
