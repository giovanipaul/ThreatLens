from datetime import UTC, datetime, timedelta

import pytest

from app.detection.credential_stuffing import CredentialStuffingDetector
from app.models.security_alert import AlertSeverity, AlertType
from app.models.security_event import AuthenticationResult, SecurityEvent


def make_event(
    minute: int,
    *,
    source_ip: str = "203.0.113.10",
    username: str = "alice",
    result: AuthenticationResult = AuthenticationResult.SUCCESS,
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


def distinct_ip_events(count: int) -> list[SecurityEvent]:
    return [
        make_event(minute, source_ip=f"203.0.113.{minute + 1}")
        for minute in range(count)
    ]


def test_detects_successes_from_many_ips_at_threshold() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )

    alerts = detector.detect(distinct_ip_events(5))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.alert_type == AlertType.CREDENTIAL_STUFFING
    assert alert.severity == AlertSeverity.MEDIUM
    assert alert.event_count == 5
    assert alert.usernames == ["alice"]
    assert str(alert.source_ip) == "203.0.113.5"
    assert "5 distinct source IPs" in alert.description


def test_ignores_fewer_ips_than_threshold() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )

    assert detector.detect(distinct_ip_events(4)) == []


def test_detects_failed_attempts() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )
    events = [
        make_event(
            minute,
            source_ip=f"203.0.113.{minute + 1}",
            result=AuthenticationResult.FAILURE,
        )
        for minute in range(5)
    ]

    alerts = detector.detect(events)
    assert len(alerts) == 1
    assert "Authentication attempts" in alerts[0].description


def test_ignores_ips_spread_across_users() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )
    events = [
        make_event(
            minute,
            source_ip=f"203.0.113.{minute + 1}",
            username=f"user-{minute}",
        )
        for minute in range(5)
    ]

    assert detector.detect(events) == []


def test_ignores_ips_outside_window() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )
    events = [
        make_event(minute * 5, source_ip=f"203.0.113.{minute + 1}")
        for minute in range(5)
    ]

    assert detector.detect(events) == []


def test_marks_high_severity_at_twice_threshold() -> None:
    detector = CredentialStuffingDetector(
        ip_threshold=5, window=timedelta(minutes=10)
    )

    alerts = detector.detect(distinct_ip_events(10))

    assert len(alerts) == 1
    assert alerts[0].severity == AlertSeverity.HIGH
    assert alerts[0].event_count == 10


def test_rejects_invalid_configuration() -> None:
    with pytest.raises(ValueError, match="IP threshold"):
        CredentialStuffingDetector(ip_threshold=1)
    with pytest.raises(ValueError, match="Detection window"):
        CredentialStuffingDetector(window=timedelta(0))
