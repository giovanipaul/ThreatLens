from datetime import UTC, datetime, timedelta

import pytest

from app.detection.brute_force import BruteForceDetector
from app.models.security_alert import AlertSeverity, AlertType
from app.models.security_event import AuthenticationResult, SecurityEvent


def make_event(
    minute: int,
    *,
    source_ip: str = "203.0.113.10",
    username: str = "root",
    result: AuthenticationResult = AuthenticationResult.FAILURE,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 7, 23, 21, minute, tzinfo=UTC),
        hostname="web-01",
        service="sshd",
        result=result,
        username=username,
        source_ip=source_ip,
        source_port=49211,
        protocol="password",
        raw_message="test authentication event",
    )


def test_detects_failures_at_threshold_within_window() -> None:
    detector = BruteForceDetector(failure_threshold=5, window=timedelta(minutes=5))
    events = [make_event(minute) for minute in range(5)]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == AlertType.BRUTE_FORCE
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.event_count == 5
    assert alert.usernames == ["root"]
    assert str(alert.source_ip) == "203.0.113.10"


def test_does_not_alert_when_failures_fall_outside_window() -> None:
    detector = BruteForceDetector(failure_threshold=3, window=timedelta(minutes=2))
    events = [make_event(0), make_event(3), make_event(6)]

    assert detector.detect(events) == []


def test_ignores_successful_logins() -> None:
    detector = BruteForceDetector(failure_threshold=3)
    events = [
        make_event(0),
        make_event(1),
        make_event(2, result=AuthenticationResult.SUCCESS),
    ]

    assert detector.detect(events) == []


def test_keeps_source_ips_separate() -> None:
    detector = BruteForceDetector(failure_threshold=3)
    events = [
        make_event(0, source_ip="203.0.113.10"),
        make_event(1, source_ip="203.0.113.10"),
        make_event(0, source_ip="198.51.100.24"),
        make_event(1, source_ip="198.51.100.24"),
    ]

    assert detector.detect(events) == []


def test_reports_multiple_usernames_and_high_severity() -> None:
    detector = BruteForceDetector(failure_threshold=3)
    usernames = ["admin", "root", "deploy", "admin", "root", "guest"]
    events = [
        make_event(index, username=username)
        for index, username in enumerate(usernames)
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert alerts[0].event_count == 6
    assert alerts[0].usernames == ["admin", "deploy", "guest", "root"]


@pytest.mark.parametrize(
    ("threshold", "window"),
    [
        (1, timedelta(minutes=5)),
        (5, timedelta(0)),
        (5, timedelta(seconds=-1)),
    ],
)
def test_rejects_invalid_configuration(
    threshold: int,
    window: timedelta,
) -> None:
    with pytest.raises(ValueError):
        BruteForceDetector(failure_threshold=threshold, window=window)

