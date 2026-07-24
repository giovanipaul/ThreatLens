from collections import defaultdict
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.models.security_event import AuthenticationResult, SecurityEvent


class SuspiciousSuccessDetector:
    """Detect a successful login following repeated failures from one source."""

    def __init__(
        self,
        failure_threshold: int = 3,
        window: timedelta = timedelta(minutes=10),
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("Failure threshold must be at least 1.")
        if window <= timedelta(0):
            raise ValueError("Detection window must be greater than zero.")

        self.failure_threshold = failure_threshold
        self.window = window

    def detect(self, events: list[SecurityEvent]) -> list[SecurityAlert]:
        events_by_ip: dict[
            IPv4Address | IPv6Address,
            list[SecurityEvent],
        ] = defaultdict(list)
        for event in events:
            events_by_ip[event.source_ip].append(event)

        alerts = []
        for source_ip, source_events in events_by_ip.items():
            alerts.extend(self._detect_for_source(source_ip, source_events))

        return sorted(alerts, key=lambda alert: alert.started_at)

    def _detect_for_source(
        self,
        source_ip: IPv4Address | IPv6Address,
        events: list[SecurityEvent],
    ) -> list[SecurityAlert]:
        failures: list[SecurityEvent] = []
        alerts = []

        for event in sorted(events, key=lambda item: item.timestamp):
            failures = [
                failure
                for failure in failures
                if event.timestamp - failure.timestamp <= self.window
            ]

            if event.result == AuthenticationResult.FAILURE:
                failures.append(event)
                continue

            if len(failures) >= self.failure_threshold:
                alerts.append(self._create_alert(source_ip, failures, event))
                failures = []

        return alerts

    def _create_alert(
        self,
        source_ip: IPv4Address | IPv6Address,
        failures: list[SecurityEvent],
        successful_event: SecurityEvent,
    ) -> SecurityAlert:
        usernames = sorted(
            {
                successful_event.username,
                *(failure.username for failure in failures),
            }
        )
        return SecurityAlert(
            alert_type=AlertType.SUCCESS_AFTER_FAILURES,
            severity=AlertSeverity.HIGH,
            title="Successful SSH login after repeated failures",
            description=(
                f"Successful authentication for {successful_event.username} from "
                f"{source_ip} followed {len(failures)} recent failed attempts."
            ),
            source_ip=source_ip,
            started_at=failures[0].timestamp,
            ended_at=successful_event.timestamp,
            event_count=len(failures) + 1,
            usernames=usernames,
        )

