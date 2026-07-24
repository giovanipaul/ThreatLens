import re
from datetime import UTC, datetime, tzinfo

from pydantic import ValidationError

from app.models.security_event import AuthenticationResult, SecurityEvent


class LinuxAuthLogParser:
    """Parse common OpenSSH authentication entries from Linux auth logs."""

    _SYSLOG_PATTERN = re.compile(
        r"^(?P<month>[A-Z][a-z]{2})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>[\w.-]+)(?:\[\d+])?:\s+"
        r"(?P<message>.+)$"
    )
    _SSH_PATTERN = re.compile(
        r"^(?P<result>Accepted|Failed)\s+"
        r"(?P<protocol>\S+)\s+"
        r"for\s+"
        r"(?:(?P<invalid>invalid user)\s+)?"
        r"(?P<username>\S+)\s+"
        r"from\s+"
        r"(?P<source_ip>\S+)\s+"
        r"port\s+"
        r"(?P<source_port>\d+)"
        r"(?:\s+ssh\d*)?"
        r"(?:\s+.*)?$"
    )

    def __init__(
        self,
        year: int | None = None,
        event_timezone: tzinfo = UTC,
    ) -> None:
        self.event_timezone = event_timezone
        self.year = year or datetime.now(event_timezone).year

    def parse_line(self, line: str) -> SecurityEvent | None:
        """Return a normalized event, or None for unsupported/malformed input."""
        clean_line = line.strip()
        if not clean_line:
            return None

        syslog_match = self._SYSLOG_PATTERN.match(clean_line)
        if not syslog_match:
            return None

        ssh_match = self._SSH_PATTERN.match(syslog_match.group("message"))
        if not ssh_match:
            return None

        try:
            timestamp = datetime.strptime(
                (
                    f"{self.year} {syslog_match.group('month')} "
                    f"{syslog_match.group('day')} {syslog_match.group('time')}"
                ),
                "%Y %b %d %H:%M:%S",
            ).replace(tzinfo=self.event_timezone)
            return SecurityEvent(
                timestamp=timestamp,
                hostname=syslog_match.group("hostname"),
                service=syslog_match.group("service"),
                result=(
                    AuthenticationResult.SUCCESS
                    if ssh_match.group("result") == "Accepted"
                    else AuthenticationResult.FAILURE
                ),
                username=ssh_match.group("username"),
                source_ip=ssh_match.group("source_ip"),
                source_port=int(ssh_match.group("source_port")),
                protocol=ssh_match.group("protocol"),
                invalid_user=ssh_match.group("invalid") is not None,
                raw_message=clean_line,
            )
        except (ValueError, ValidationError):
            return None

    def parse_lines(self, lines: list[str]) -> list[SecurityEvent]:
        """Parse supported entries while safely skipping unrelated lines."""
        events = []
        for line in lines:
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        return events
