from datetime import UTC, datetime

from sqlalchemy import DateTime, Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.types import TypeDecorator


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    """Store UTC datetimes in SQLite and restore timezone information on read."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: object,
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("Timezone-aware datetime required.")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: object,
    ) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC)


def create_database_engine(database_url: str = "sqlite:///threatlens.db") -> Engine:
    return create_engine(
        database_url,
        connect_args={"check_same_thread": False},
    )


def create_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)

