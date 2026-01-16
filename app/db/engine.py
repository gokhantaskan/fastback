from collections.abc import Generator

from sqlmodel import Session, create_engine

from app.core.settings import get_settings

_settings = get_settings()

connect_args: dict[str, object] = {}
if _settings.database_url.startswith("sqlite"):
    # Required for SQLite when used with FastAPI across threads.
    connect_args = {"check_same_thread": False}

engine = create_engine(_settings.database_url, echo=False, connect_args=connect_args)


def get_session() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session
