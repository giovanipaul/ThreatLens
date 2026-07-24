from datetime import UTC, datetime, timedelta

import pytest

from app.detection import SuspiciousSuccessDetector
from app.models.security_alert import AlertSeverity, AlertType
from app.models.security_event import AuthenticationResult, SecurityEvent


def make_event(
    minute: int,
    result: AuthenticationResult,
    *,
    source_ip: str = "203.0.113.10",
    username: str = "admin",
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 7, 23, 21, minute, tzinfo=UTC),
        hostname="web-01",
        service="sshd",
        result=result,
        username=username,
        source_ip=source_ip,
        source_port=49211 + minute,
        protocol="password",
        raw_message=f"event-{minute}-{result.value}-{source_ip}-{username}",
    )


def test_detects_success_after_repeated_failures() -> None:
    detector = SuspiciousSuccessDetector(failure_threshold=3)
    events = [
        make_event(0, AuthenticationResult.FAILURE),
        make_event(1, AuthenticationResult.FAILURE),
        make_event(2, AuthenticationResult.FAILURE),
        make_event(3, AuthenticationResult.SUCCESS),
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == AlertType.SUCCESS_AFTER_FAILURES
    assert alert.severity == AlertSeverity.HIGH
    assert alert.event_count == 4
    assert alert.usernames == ["admin"]


def test_does_not_trigger_below_threshold() -> None:
    detector = SuspiciousSuccessDetector(failure_threshold=3)
    events = [
        make_event(0, AuthenticationResult.FAILURE),
        make_event(1, AuthenticationResult.FAILURE),
        make_event(2, AuthenticationResult.SUCCESS),
    ]

    assert detector.detect(events) == []


def test_ignores_expired_and_different_source_failures() -> None:
    detector = SuspiciousSuccessDetector(
        failure_threshold=2,
        window=timedelta(minutes=2),
    )
    events = [
        make_event(0, AuthenticationResult.FAILURE),
        make_event(1, AuthenticationResult.FAILURE, source_ip="198.51.100.24"),
        make_event(4, AuthenticationResult.FAILURE),
        make_event(5, AuthenticationResult.SUCCESS),
    ]

    assert detector.detect(events) == []


def test_includes_failed_and_successful_usernames() -> None:
    detector = SuspiciousSuccessDetector(failure_threshold=2)
    events = [
        make_event(0, AuthenticationResult.FAILURE, username="root"),
        make_event(1, AuthenticationResult.FAILURE, username="admin"),
        make_event(2, AuthenticationResult.SUCCESS, username="admin"),
    ]

    alerts = detector.detect(events)

    assert alerts[0].usernames == ["admin", "root"]


def test_clears_failures_after_alert_to_avoid_duplicate_findings() -> None:
    detector = SuspiciousSuccessDetector(failure_threshold=2)
    events = [
        make_event(0, AuthenticationResult.FAILURE),
        make_event(1, AuthenticationResult.FAILURE),
        make_event(2, AuthenticationResult.SUCCESS),
        make_event(3, AuthenticationResult.SUCCESS),
    ]

    assert len(detector.detect(events)) == 1


@pytest.mark.parametrize(
    ("threshold", "window"),
    [
        (0, timedelta(minutes=10)),
        (3, timedelta(0)),
        (3, timedelta(seconds=-1)),
    ],
)
def test_rejects_invalid_configuration(
    threshold: int,
    window: timedelta,
) -> None:
    with pytest.raises(ValueError):
        SuspiciousSuccessDetector(failure_threshold=threshold, window=window)

