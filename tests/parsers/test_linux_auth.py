from datetime import UTC, datetime
from ipaddress import ip_address

from app.models.security_event import AuthenticationResult
from app.parsers.linux_auth import LinuxAuthLogParser


def test_parses_failed_password_event() -> None:
    parser = LinuxAuthLogParser(year=2026)

    event = parser.parse_line(
        "Jul 23 21:14:05 web-01 sshd[1852]: "
        "Failed password for root from 203.0.113.10 port 49211 ssh2"
    )

    assert event is not None
    assert event.timestamp == datetime(2026, 7, 23, 21, 14, 5, tzinfo=UTC)
    assert event.hostname == "web-01"
    assert event.service == "sshd"
    assert event.result == AuthenticationResult.FAILURE
    assert event.username == "root"
    assert event.source_ip == ip_address("203.0.113.10")
    assert event.source_port == 49211
    assert event.protocol == "password"
    assert event.invalid_user is False


def test_parses_invalid_user_event() -> None:
    parser = LinuxAuthLogParser(year=2026)

    event = parser.parse_line(
        "Jul 23 21:15:07 web-01 sshd[1853]: "
        "Failed password for invalid user admin2 from 198.51.100.24 port 55210 ssh2"
    )

    assert event is not None
    assert event.username == "admin2"
    assert event.invalid_user is True
    assert event.result == AuthenticationResult.FAILURE


def test_parses_successful_public_key_login_with_ipv6() -> None:
    parser = LinuxAuthLogParser(year=2026)

    event = parser.parse_line(
        "Jul 23 21:20:11 api-01 sshd[1900]: "
        "Accepted publickey for deploy from 2001:db8::8 port 50100 ssh2"
    )

    assert event is not None
    assert event.result == AuthenticationResult.SUCCESS
    assert event.protocol == "publickey"
    assert event.source_ip == ip_address("2001:db8::8")


def test_skips_unrelated_and_malformed_lines() -> None:
    parser = LinuxAuthLogParser(year=2026)

    assert parser.parse_line("") is None
    assert parser.parse_line("not a syslog entry") is None
    assert (
        parser.parse_line(
            "Jul 23 21:20:11 api-01 sudo: deploy opened a session for root"
        )
        is None
    )
    assert (
        parser.parse_line(
            "Jul 23 21:20:11 api-01 sshd[1900]: "
            "Failed password for root from invalid-ip port 50100 ssh2"
        )
        is None
    )


def test_parse_lines_returns_only_supported_events() -> None:
    parser = LinuxAuthLogParser(year=2026)
    lines = [
        (
            "Jul 23 21:14:05 web-01 sshd[1852]: "
            "Failed password for root from 203.0.113.10 port 49211 ssh2"
        ),
        "Jul 23 21:14:06 web-01 cron[100]: job completed",
        (
            "Jul 23 21:14:07 web-01 sshd[1854]: "
            "Accepted password for analyst from 192.0.2.5 port 41000 ssh2"
        ),
    ]

    events = parser.parse_lines(lines)

    assert len(events) == 2
    assert [event.result for event in events] == [
        AuthenticationResult.FAILURE,
        AuthenticationResult.SUCCESS,
    ]
