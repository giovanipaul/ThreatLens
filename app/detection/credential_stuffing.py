from collections import Counter, defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.models.security_event import AuthenticationResult, SecurityEvent


class CredentialStuffingDetector:
    """Detect one username authenticating from many distinct source IPs."""

    def __init__(
        self,
        ip_threshold: int = 5,
        window: timedelta = timedelta(minutes=10),
    ) -> None:
        if ip_threshold < 2:
            raise ValueError("IP threshold must be at least 2.")
        if window <= timedelta(0):
            raise ValueError("Detection window must be greater than zero.")

        self.ip_threshold = ip_threshold
        self.window = window

    def detect(self, events: list[SecurityEvent]) -> list[SecurityAlert]:
        successes_by_user: dict[str, list[SecurityEvent]] = defaultdict(list)

        for event in events:
            if event.result == AuthenticationResult.SUCCESS:
                successes_by_user[event.username].append(event)

        alerts = []
        for username, successes in successes_by_user.items():
            suspicious_window = self._most_diverse_window(successes)
            source_ips = {event.source_ip for event in suspicious_window}
            if len(source_ips) >= self.ip_threshold:
                alerts.append(
                    self._create_alert(username, suspicious_window, source_ips)
                )

        return sorted(alerts, key=lambda alert: alert.started_at)

    def _most_diverse_window(
        self,
        successes: list[SecurityEvent],
    ) -> list[SecurityEvent]:
        ordered = sorted(successes, key=lambda event: event.timestamp)
        ip_counts: Counter[IPv4Address | IPv6Address] = Counter()
        best: list[SecurityEvent] = []
        best_unique_count = 0
        left = 0

        for right, current_event in enumerate(ordered):
            ip_counts[current_event.source_ip] += 1

            while current_event.timestamp - ordered[left].timestamp > self.window:
                expired_ip = ordered[left].source_ip
                ip_counts[expired_ip] -= 1
                if ip_counts[expired_ip] == 0:
                    del ip_counts[expired_ip]
                left += 1

            candidate = ordered[left : right + 1]
            unique_count = len(ip_counts)
            if unique_count > best_unique_count or (
                unique_count == best_unique_count and len(candidate) > len(best)
            ):
                best = candidate
                best_unique_count = unique_count

        return best

    def _create_alert(
        self,
        username: str,
        events: list[SecurityEvent],
        source_ips: set[IPv4Address | IPv6Address],
    ) -> SecurityAlert:
        unique_count = len(source_ips)
        severity = (
            AlertSeverity.HIGH
            if unique_count >= self.ip_threshold * 2
            else AlertSeverity.MEDIUM
        )
        ordered_ips = sorted(str(ip) for ip in source_ips)

        return SecurityAlert(
            alert_type=AlertType.CREDENTIAL_STUFFING,
            severity=severity,
            title="Possible credential-stuffing attack",
            description=(
                f"Successful authentication for {username} from "
                f"{unique_count} distinct source IPs "
                f"({', '.join(ordered_ips)}) within {self._format_window()}."
            ),
            source_ip=events[-1].source_ip,
            started_at=events[0].timestamp,
            ended_at=events[-1].timestamp,
            event_count=len(events),
            usernames=[username],
        )

    def _format_window(self) -> str:
        seconds = int(self.window.total_seconds())
        if seconds % 60 == 0:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        return f"{seconds} seconds"
