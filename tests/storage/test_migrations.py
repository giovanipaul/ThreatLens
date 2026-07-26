from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from app.storage import records  # noqa: F401
from app.storage.database import Base, create_database_engine
from app.storage.migrations import PROJECT_ROOT, run_migrations

EXPECTED_TABLES = {
    "alembic_version",
    "alert_history",
    "alert_states",
    "audit_log",
    "security_alerts",
    "security_events",
    "user_sessions",
    "users",
}


def test_upgrades_empty_database_to_latest_schema(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    try:
        run_migrations(engine)

        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
        with engine.connect() as connection:
            version = connection.scalar(text("select version_num from alembic_version"))
        assert version == "0001"
    finally:
        engine.dispose()


def test_baselines_existing_pre_alembic_database(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    try:
        Base.metadata.create_all(engine)
        assert "alembic_version" not in inspect(engine).get_table_names()

        run_migrations(engine)

        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
        with engine.connect() as connection:
            version = connection.scalar(text("select version_num from alembic_version"))
        assert version == "0001"
    finally:
        engine.dispose()


def test_migrations_are_idempotent(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'repeat.db'}")
    try:
        run_migrations(engine)
        run_migrations(engine)

        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    finally:
        engine.dispose()


def test_initial_migration_is_reversible(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'reversible.db'}")
    configuration = Config(PROJECT_ROOT / "alembic.ini")
    try:
        run_migrations(engine)
        with engine.begin() as connection:
            configuration.attributes["connection"] = connection
            command.downgrade(configuration, "base")
        assert set(inspect(engine).get_table_names()) == {"alembic_version"}

        run_migrations(engine)
        assert set(inspect(engine).get_table_names()) == EXPECTED_TABLES
    finally:
        engine.dispose()
