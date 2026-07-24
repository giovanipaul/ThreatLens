from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.detection import BruteForceDetector
from app.models.security_alert import AlertSeverity, AlertStatus
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.storage import ThreatRepository


@pytest.fixture
def repository(tmp_path: Path) -> Iterator[ThreatRepository]:
    database_path = tmp_path / "test.db"
    repo = ThreatRepository(f"sqlite:///{database_path}")
    repo.initialize()
    try:
        yield repo
    finally:
        repo.close()


def make_event(
    minute: int = 0,
    *,
    source_ip: str = "203.0.113.10",
    result: AuthenticationResult = AuthenticationResult.FAILURE,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 7, 23, 21, minute, tzinfo=UTC),
        hostname="web-01",
        service="sshd",
        result=result,
        username="root",
        source_ip=source_ip,
        source_port=49211,
        protocol="password",
        raw_message=f"event-{minute}-{source_ip}-{result.value}",
    )


def test_persists_and_restores_event(repository: ThreatRepository) -> None:
    original = make_event()

    assert repository.save_events([original]) == 1

    restored = repository.list_events()
    assert restored == [original]
    assert restored[0].timestamp.tzinfo == UTC


def test_skips_duplicate_events(repository: ThreatRepository) -> None:
    event = make_event()

    assert repository.save_events([event]) == 1
    assert repository.save_events([event]) == 0
    assert len(repository.list_events()) == 1


def test_filters_events(repository: ThreatRepository) -> None:
    repository.save_events(
        [
            make_event(source_ip="203.0.113.10"),
            make_event(
                1,
                source_ip="198.51.100.24",
                result=AuthenticationResult.SUCCESS,
            ),
        ]
    )

    failures = repository.list_events(result=AuthenticationResult.FAILURE)
    selected_ip = repository.list_events(source_ip="198.51.100.24")

    assert len(failures) == 1
    assert failures[0].result == AuthenticationResult.FAILURE
    assert len(selected_ip) == 1
    assert str(selected_ip[0].source_ip) == "198.51.100.24"


def test_persists_and_filters_alerts(repository: ThreatRepository) -> None:
    events = [make_event(minute) for minute in range(5)]
    alert = BruteForceDetector().detect(events)[0]

    assert repository.save_alerts([alert]) == 1
    assert repository.save_alerts([alert]) == 0

    restored = repository.list_alerts(severity=AlertSeverity.MEDIUM)
    assert restored == [alert]


def test_manages_alert_lifecycle(repository: ThreatRepository) -> None:
    events = [make_event(minute) for minute in range(5)]
    repository.save_alerts(BruteForceDetector().detect(events))

    initial = repository.list_managed_alerts()
    assert initial[0].status == AlertStatus.OPEN

    assert repository.set_alert_status(
        initial[0].id,
        AlertStatus.ACKNOWLEDGED,
    )
    acknowledged = repository.list_managed_alerts(
        status=AlertStatus.ACKNOWLEDGED
    )
    assert len(acknowledged) == 1
    assert acknowledged[0].status == AlertStatus.ACKNOWLEDGED

    assert repository.set_alert_status(
        initial[0].id,
        AlertStatus.RESOLVED,
    )
    assert repository.list_managed_alerts(status=AlertStatus.OPEN) == []
    assert len(repository.list_managed_alerts(status=AlertStatus.RESOLVED)) == 1


def test_rejects_status_update_for_missing_alert(
    repository: ThreatRepository,
) -> None:
    assert not repository.set_alert_status(999, AlertStatus.RESOLVED)


@pytest.mark.parametrize("limit", [0, 1001])
def test_rejects_invalid_query_limit(
    repository: ThreatRepository,
    limit: int,
) -> None:
    with pytest.raises(ValueError):
        repository.list_events(limit=limit)
