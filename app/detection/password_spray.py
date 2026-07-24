from collections import Counter, defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.models.security_event import AuthenticationResult, SecurityEvent


class PasswordSprayDetector:
    """Detect one source attempting authentication against many usernames."""

    def __init__(
        self,
        username_threshold: int = 5,
        window: timedelta = timedelta(minutes=10),
    ) -> None:
        if username_threshold < 2:
            raise ValueError("Username threshold must be at least 2.")
        if window <= timedelta(0):
            raise ValueError("Detection window must be greater than zero.")

        self.username_threshold = username_threshold
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
            suspicious_window = self._most_diverse_window(failures)
            usernames = {event.username for event in suspicious_window}
            if len(usernames) >= self.username_threshold:
                alerts.append(
                    self._create_alert(source_ip, suspicious_window, usernames)
                )

        return sorted(alerts, key=lambda alert: alert.started_at)

    def _most_diverse_window(
        self,
        failures: list[SecurityEvent],
    ) -> list[SecurityEvent]:
        ordered = sorted(failures, key=lambda event: event.timestamp)
        username_counts: Counter[str] = Counter()
        best: list[SecurityEvent] = []
        best_unique_count = 0
        left = 0

        for right, current_event in enumerate(ordered):
            username_counts[current_event.username] += 1

            while current_event.timestamp - ordered[left].timestamp > self.window:
                expired_username = ordered[left].username
                username_counts[expired_username] -= 1
                if username_counts[expired_username] == 0:
                    del username_counts[expired_username]
                left += 1

            candidate = ordered[left : right + 1]
            unique_count = len(username_counts)
            if unique_count > best_unique_count or (
                unique_count == best_unique_count and len(candidate) > len(best)
            ):
                best = candidate
                best_unique_count = unique_count

        return best

    def _create_alert(
        self,
        source_ip: IPv4Address | IPv6Address,
        events: list[SecurityEvent],
        usernames: set[str],
    ) -> SecurityAlert:
        unique_count = len(usernames)
        severity = (
            AlertSeverity.HIGH
            if unique_count >= self.username_threshold * 2
            else AlertSeverity.MEDIUM
        )

        return SecurityAlert(
            alert_type=AlertType.PASSWORD_SPRAYING,
            severity=severity,
            title="Possible SSH password-spraying attack",
            description=(
                f"Detected failed authentication attempts against {unique_count} "
                f"usernames from {source_ip} within {self._format_window()}."
            ),
            source_ip=source_ip,
            started_at=events[0].timestamp,
            ended_at=events[-1].timestamp,
            event_count=len(events),
            usernames=sorted(usernames),
        )

    def _format_window(self) -> str:
        seconds = int(self.window.total_seconds())
        if seconds % 60 == 0:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{seconds} seconds"

