from datetime import UTC, datetime, timedelta

import pytest

from app.detection import PasswordSprayDetector
from app.models.security_alert import AlertSeverity, AlertType
from app.models.security_event import AuthenticationResult, SecurityEvent


def make_event(
    minute: int,
    username: str,
    *,
    source_ip: str = "203.0.113.10",
    result: AuthenticationResult = AuthenticationResult.FAILURE,
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
        raw_message=f"event-{minute}-{username}-{source_ip}-{result.value}",
    )


def test_detects_multiple_targeted_usernames() -> None:
    detector = PasswordSprayDetector(
        username_threshold=5,
        window=timedelta(minutes=10),
    )
    events = [
        make_event(index, username)
        for index, username in enumerate(
            ["admin", "root", "deploy", "analyst", "service"]
        )
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == AlertType.PASSWORD_SPRAYING
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.event_count == 5
    assert alert.usernames == ["admin", "analyst", "deploy", "root", "service"]


def test_repeated_attempts_against_one_user_do_not_trigger() -> None:
    detector = PasswordSprayDetector(username_threshold=3)
    events = [make_event(index, "root") for index in range(5)]

    assert detector.detect(events) == []


def test_keeps_source_ips_separate() -> None:
    detector = PasswordSprayDetector(username_threshold=3)
    events = [
        make_event(0, "admin", source_ip="203.0.113.10"),
        make_event(1, "root", source_ip="203.0.113.10"),
        make_event(0, "deploy", source_ip="198.51.100.24"),
    ]

    assert detector.detect(events) == []


def test_ignores_successful_logins_and_expired_failures() -> None:
    detector = PasswordSprayDetector(
        username_threshold=3,
        window=timedelta(minutes=2),
    )
    events = [
        make_event(0, "admin"),
        make_event(1, "root", result=AuthenticationResult.SUCCESS),
        make_event(4, "deploy"),
        make_event(5, "service"),
    ]

    assert detector.detect(events) == []


def test_assigns_high_severity_at_twice_threshold() -> None:
    detector = PasswordSprayDetector(username_threshold=3)
    events = [
        make_event(index, username)
        for index, username in enumerate(
            ["admin", "root", "deploy", "analyst", "service", "guest"]
        )
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH


@pytest.mark.parametrize(
    ("threshold", "window"),
    [
        (1, timedelta(minutes=10)),
        (5, timedelta(0)),
        (5, timedelta(seconds=-1)),
    ],
)
def test_rejects_invalid_configuration(
    threshold: int,
    window: timedelta,
) -> None:
    with pytest.raises(ValueError):
        PasswordSprayDetector(username_threshold=threshold, window=window)

