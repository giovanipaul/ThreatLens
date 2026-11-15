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
    "explanation_attempts",
    "explanation_cache",
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
        assert version == "0002"
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
        assert version == "0002"
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


def test_upgrades_previous_schema_without_losing_users(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'upgrade.db'}")
    configuration = Config(PROJECT_ROOT / "alembic.ini")
    try:
        with engine.begin() as connection:
            configuration.attributes["connection"] = connection
            command.upgrade(configuration, "0001")
            connection.execute(text(
                "INSERT INTO users (username, password_hash, role, active, created_at) "
                "VALUES ('analyst', 'hash', 'analyst', 1, '2026-01-01 00:00:00')"
            ))
        run_migrations(engine)
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT username FROM users")) == "analyst"
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0002"
        assert "explanation_cache" in inspect(engine).get_table_names()
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
