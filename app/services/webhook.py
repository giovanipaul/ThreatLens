"""Outbound webhook delivery for high-severity alerts."""

import httpx

from app.models.security_alert import AlertSeverity, SecurityAlert

WEBHOOK_EVENT = "threatlens.alert.high"


def alert_webhook_payload(alert: SecurityAlert) -> dict[str, object]:
    """Build the JSON payload posted to the configured webhook URL."""
    return {
        "event": WEBHOOK_EVENT,
        "alert_type": alert.alert_type.value,
        "severity": alert.severity.value,
        "title": alert.title,
        "description": alert.description,
        "source_ip": str(alert.source_ip),
        "started_at": alert.started_at.isoformat(),
        "ended_at": alert.ended_at.isoformat(),
        "event_count": alert.event_count,
        "usernames": list(alert.usernames),
    }


def dispatch_alert_webhook(
    url: str,
    alert: SecurityAlert,
    *,
    timeout_seconds: float = 5,
    client: httpx.Client | None = None,
) -> bool:
    """Post one high-severity alert to a webhook URL.

    Returns True when the endpoint accepts the payload. Delivery failures
    never raise: a dead webhook must not block log imports.
    """
    if alert.severity != AlertSeverity.HIGH:
        return False
    try:
        if client is not None:
            response = client.post(
                url,
                json=alert_webhook_payload(alert),
                timeout=timeout_seconds,
            )
        else:
            response = httpx.post(
                url,
                json=alert_webhook_payload(alert),
                timeout=timeout_seconds,
            )
        response.raise_for_status()
    except (httpx.HTTPError, ValueError):
        return False
    return True
