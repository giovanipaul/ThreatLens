from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect

from app.storage.database import Base

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LEGACY_TABLES = {"security_events", "security_alerts"}


def run_migrations(engine: Engine) -> None:
    """Upgrade a new database or safely baseline a legacy ThreatLens schema."""
    configuration = Config(PROJECT_ROOT / "alembic.ini")
    with engine.begin() as connection:
        configuration.attributes["connection"] = connection
        tables = set(inspect(connection).get_table_names())
        if tables & LEGACY_TABLES and "alembic_version" not in tables:
            Base.metadata.create_all(connection)
            command.stamp(configuration, "head")
        else:
            command.upgrade(configuration, "head")
