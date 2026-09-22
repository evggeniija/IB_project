"""SQLAlchemy engine, session, and schema setup.

Importing this module has no filesystem side effects: no engine is created
and no database file is touched until ``create_engine_for_url``/``init_db``
are called explicitly.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DEFAULT_DATABASE_URL = "sqlite:///data/ibe.db"


class Base(DeclarativeBase):
    pass


def create_engine_for_url(url: str = DEFAULT_DATABASE_URL, **kwargs: object) -> Engine:
    """Create the SQLAlchemy engine for ``url``.

    For a file-based SQLite URL, the database file's parent directory is
    created first if missing -- sqlite3 cannot create the file itself
    inside a nonexistent directory and instead fails with "unable to open
    database file". This mirrors ``pkg.load_or_create_master_secret``,
    which already creates its own key directory the same way.

    For SQLite, every new DBAPI connection also gets
    ``PRAGMA foreign_keys=ON`` (SQLite does not enforce foreign keys by
    default, and declaring ``ForeignKey(...)`` alone has no runtime effect
    there) and a busy timeout, so that two connections racing on an atomic
    conditional UPDATE (e.g. claiming a message as processed) wait briefly
    for each other instead of failing immediately with
    "database is locked".
    """
    engine = create_engine(url, **kwargs)
    if engine.dialect.name == "sqlite":
        _ensure_sqlite_parent_directory(engine.url.database)
        _configure_sqlite_connection(engine)
    return engine


def _ensure_sqlite_parent_directory(database: str | None) -> None:
    if not database or database == ":memory:":
        return  # in-memory database, no file/directory involved
    Path(database).parent.mkdir(parents=True, exist_ok=True)


def _configure_sqlite_connection(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection: object, connection_record: object) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    """Create all tables registered on ``Base.metadata``.

    Callers must import ``app.storage.models`` first so its tables are
    registered before this runs.
    """
    Base.metadata.create_all(engine)
