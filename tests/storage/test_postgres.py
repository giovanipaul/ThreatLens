import os
from datetime import UTC, datetime

import pytest
from sqlalchemy import inspect

from app.models.security_event import AuthenticationResult, SecurityEvent
from app.storage import ThreatRepository

POSTGRES_URL = os.getenv("TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="TEST_POSTGRES_URL is required for PostgreSQL integration tests.",
)


def test_repository_and_migrations_on_postgresql() -> None:
    assert POSTGRES_URL is not None
    repository = ThreatRepository(POSTGRES_URL)
    try:
        repository.initialize()
        user = repository.create_user(
            "postgres-analyst",
            "postgres secure password",
        )
        event = SecurityEvent(
            timestamp=datetime(2026, 7, 25, 22, 30, tzinfo=UTC),
            hostname="db-test",
            service="sshd",
            result=AuthenticationResult.FAILURE,
            username="root",
            source_ip="203.0.113.50",
            source_port=22,
            protocol="password",
            raw_message="postgres-integration-event",
        )

        assert repository.save_events([event]) == 1
        assert repository.list_events() == [event]
        assert repository.authenticate(
            user.username,
            "postgres secure password",
        ) == user
        assert "alembic_version" in inspect(repository.engine).get_table_names()
    finally:
        repository.close()
