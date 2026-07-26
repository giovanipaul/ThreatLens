from datetime import UTC, datetime

from sqlalchemy.dialects import postgresql, sqlite

from app.storage import database
from app.storage.database import UTCDateTime


def test_uses_sqlite_only_connection_arguments(monkeypatch) -> None:
    calls = []
    sentinel = object()

    def fake_create_engine(url: str, **kwargs):
        calls.append((url, kwargs))
        return sentinel

    monkeypatch.setattr(database, "create_engine", fake_create_engine)

    assert database.create_database_engine("sqlite:///test.db") is sentinel
    assert (
        database.create_database_engine(
            "postgresql+psycopg://user:password@db/threatlens"
        )
        is sentinel
    )
    assert calls[0][1]["connect_args"] == {"check_same_thread": False}
    assert calls[1][1]["connect_args"] == {}


def test_utc_datetime_adapts_to_database_dialect() -> None:
    timestamp = datetime(2026, 7, 25, 22, 30, tzinfo=UTC)
    column_type = UTCDateTime()

    sqlite_value = column_type.process_bind_param(timestamp, sqlite.dialect())
    postgres_value = column_type.process_bind_param(
        timestamp,
        postgresql.dialect(),
    )

    assert sqlite_value == timestamp.replace(tzinfo=None)
    assert postgres_value == timestamp
    assert column_type.process_result_value(sqlite_value, sqlite.dialect()) == timestamp
    assert (
        column_type.process_result_value(postgres_value, postgresql.dialect())
        == timestamp
    )
