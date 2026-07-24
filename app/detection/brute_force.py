from collections import defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.models.security_event import AuthenticationResult, SecurityEvent


class BruteForceDetector:
    """Detect repeated authentication failures from one source IP."""

    def __init__(
        self,
        failure_threshold: int = 5,
        window: timedelta = timedelta(minutes=5),
    ) -> None:
        if failure_threshold < 2:
            raise ValueError("Failure threshold must be at least 2.")
        if window <= timedelta(0):
            raise ValueError("Detection window must be greater than zero.")

        self.failure_threshold = failure_threshold
        self.window = window

    def detect(self, events: list[SecurityEvent]) -> list[SecurityAlert]:
        failures_by_ip: dict[
            IPv4Address | IPv6Address,
            list[SecurityEvent],
        ] = defaultdict(list)

        for event in events:
            if event.result == AuthenticationResult.FAILURE:
                failures_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, failures in failures_by_ip.items():
            suspicious_window = self._largest_suspicious_window(failures)
            if len(suspicious_window) >= self.failure_threshold:
                alerts.append(self._create_alert(source_ip, suspicious_window))

        return sorted(alerts, key=lambda alert: alert.started_at)

    def _largest_suspicious_window(
        self,
        failures: list[SecurityEvent],
    ) -> list[SecurityEvent]:
        ordered = sorted(failures, key=lambda event: event.timestamp)
        largest: list[SecurityEvent] = []
        left = 0

        for right, current_event in enumerate(ordered):
            while current_event.timestamp - ordered[left].timestamp > self.window:
                left += 1

            current_window = ordered[left : right + 1]
            if len(current_window) > len(largest):
                largest = current_window

        return largest

    def _create_alert(
        self,
        source_ip: IPv4Address | IPv6Address,
        events: list[SecurityEvent],
    ) -> SecurityAlert:
        event_count = len(events)
        severity = (
            AlertSeverity.HIGH
            if event_count >= self.failure_threshold * 2
            else AlertSeverity.MEDIUM
        )
        usernames = sorted({event.username for event in events})

        return SecurityAlert(
            alert_type=AlertType.BRUTE_FORCE,
            severity=severity,
            title="Possible SSH brute-force attack",
            description=(
                f"Detected {event_count} failed authentication attempts from "
                f"{source_ip} within {self._format_window()}."
            ),
            source_ip=source_ip,
            started_at=events[0].timestamp,
            ended_at=events[-1].timestamp,
            event_count=event_count,
            usernames=usernames,
        )

    def _format_window(self) -> str:
        seconds = int(self.window.total_seconds())
        if seconds % 60 == 0:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{seconds} seconds"

