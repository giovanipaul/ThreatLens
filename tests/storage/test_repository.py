from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.auth import UserRole
from app.detection import BruteForceDetector
from app.models.security_alert import AlertSeverity, AlertStatus, AlertType
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


def test_distinguishes_credential_alerts_for_different_users(repository: ThreatRepository) -> None:
    base = BruteForceDetector().detect([make_event(i) for i in range(5)])[0]
    alice = base.model_copy(update={"alert_type": AlertType.CREDENTIAL_STUFFING, "usernames": ["alice"]})
    bob = alice.model_copy(update={"usernames": ["bob"]})
    assert repository.save_alerts([alice, bob, alice]) == 2
    assert repository.save_alerts([alice, bob]) == 0
    assert {tuple(a.usernames) for a in repository.list_alerts()} == {("alice",), ("bob",)}


def test_legacy_credential_fingerprint_deduplicates_same_user(repository: ThreatRepository) -> None:
    base = BruteForceDetector().detect([make_event(i) for i in range(5)])[0]
    alice = base.model_copy(update={"alert_type": AlertType.CREDENTIAL_STUFFING, "usernames": ["alice"]})
    record = repository._alert_to_record(alice)
    record.fingerprint = repository._alert_fingerprint(alice, legacy=True)
    with repository.sessions.begin() as session:
        session.add(record)
    bob = alice.model_copy(update={"usernames": ["bob"]})
    assert repository.save_alerts([alice, bob]) == 1
    assert repository.save_alerts([alice, bob]) == 0


def test_equal_timestamp_pagination_has_deterministic_order(repository: ThreatRepository) -> None:
    repository.save_events([make_event(source_ip=f"203.0.113.{i}") for i in range(1, 5)])
    pages = [repository.list_events(limit=1, offset=i)[0] for i in range(4)]
    assert [str(e.source_ip) for e in pages] == [f"203.0.113.{i}" for i in range(4, 0, -1)]


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


def test_appends_immutable_alert_history(repository: ThreatRepository) -> None:
    actor = repository.create_user(
        "analyst",
        "analyst secure password",
        UserRole.ANALYST,
    )
    repository.save_alerts(
        BruteForceDetector().detect([make_event(minute) for minute in range(5)])
    )
    alert_id = repository.list_managed_alerts()[0].id

    assert repository.set_alert_status(
        alert_id,
        AlertStatus.ACKNOWLEDGED,
        actor=actor,
        note="Investigating source activity.",
    )
    assert repository.set_alert_status(
        alert_id,
        AlertStatus.RESOLVED,
        actor=actor,
        note="Blocked source at the firewall.",
    )

    history = repository.list_alert_history(alert_id)
    assert history is not None
    assert len(history) == 2
    assert history[0].previous_status == "open"
    assert history[0].new_status == "acknowledged"
    assert history[0].actor_username == "analyst"
    assert history[0].note == "Investigating source activity."
    assert history[1].previous_status == "acknowledged"
    assert history[1].new_status == "resolved"
    assert history[1].note == "Blocked source at the firewall."
    assert history[0].occurred_at.tzinfo == UTC


def test_returns_none_for_missing_alert_history(
    repository: ThreatRepository,
) -> None:
    assert repository.list_alert_history(999) is None


def test_rejects_status_update_for_missing_alert(
    repository: ThreatRepository,
) -> None:
    assert not repository.set_alert_status(999, AlertStatus.RESOLVED)


def test_pages_events_and_alerts_with_offset(
    repository: ThreatRepository,
) -> None:
    repository.save_events([make_event(minute) for minute in range(5)])
    repository.save_alerts(
        BruteForceDetector().detect([make_event(minute) for minute in range(5)])
    )

    first_page = repository.list_events(limit=2, offset=0)
    second_page = repository.list_events(limit=2, offset=2)
    remainder = repository.list_events(limit=2, offset=4)
    beyond = repository.list_events(limit=2, offset=5)

    assert len(first_page) == 2
    assert len(second_page) == 2
    assert len(remainder) == 1
    assert beyond == []
    assert first_page[0].timestamp > second_page[0].timestamp
    assert repository.list_managed_alerts(limit=1, offset=1) == []
    assert len(repository.list_managed_alerts(limit=1, offset=0)) == 1


@pytest.mark.parametrize("offset", [-1])
def test_rejects_invalid_query_offset(
    repository: ThreatRepository,
    offset: int,
) -> None:
    with pytest.raises(ValueError):
        repository.list_events(offset=offset)


@pytest.mark.parametrize("limit", [0, 1001])
def test_rejects_invalid_query_limit(
    repository: ThreatRepository,
    limit: int,
) -> None:
    with pytest.raises(ValueError):
        repository.list_events(limit=limit)
