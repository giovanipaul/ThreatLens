import json
from datetime import UTC, datetime

import httpx
import pytest

from app.config import DetectionSettings
from app.models.security_alert import (
    AlertSeverity,
    AlertType,
    SecurityAlert,
)
from app.services.webhook import (
    WEBHOOK_EVENT,
    alert_webhook_payload,
    dispatch_alert_webhook,
)


def make_alert(
    *,
    severity: AlertSeverity = AlertSeverity.HIGH,
) -> SecurityAlert:
    return SecurityAlert(
        alert_type=AlertType.BRUTE_FORCE,
        severity=severity,
        title="Possible SSH brute-force attack",
        description="Detected 10 failed authentication attempts.",
        source_ip="203.0.113.10",
        started_at=datetime(2026, 7, 23, 21, 14, tzinfo=UTC),
        ended_at=datetime(2026, 7, 23, 21, 15, tzinfo=UTC),
        event_count=10,
        usernames=["root"],
    )


def test_payload_carries_structured_alert_fields() -> None:
    payload = alert_webhook_payload(make_alert())

    assert payload == {
        "event": WEBHOOK_EVENT,
        "alert_type": "brute_force",
        "severity": "high",
        "title": "Possible SSH brute-force attack",
        "description": "Detected 10 failed authentication attempts.",
        "source_ip": "203.0.113.10",
        "started_at": "2026-07-23T21:14:00+00:00",
        "ended_at": "2026-07-23T21:15:00+00:00",
        "event_count": 10,
        "usernames": ["root"],
    }


def test_dispatch_posts_payload_and_returns_true() -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    client = httpx.Client(transport=httpx.MockTransport(handler))

    assert dispatch_alert_webhook(
        "https://hooks.example.test/threatlens",
        make_alert(),
        client=client,
    )
    assert len(seen) == 1
    assert seen[0].headers["content-type"] == "application/json"
    assert json.loads(seen[0].content) == alert_webhook_payload(
        make_alert()
    )


def test_dispatch_returns_false_on_error_response() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(500, json={"error": "down"})
        )
    )

    assert not dispatch_alert_webhook(
        "https://hooks.example.test/threatlens",
        make_alert(),
        client=client,
    )


def test_dispatch_returns_false_on_connection_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable", request=request)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    assert not dispatch_alert_webhook(
        "https://hooks.example.test/threatlens",
        make_alert(),
        client=client,
    )


def test_dispatch_skips_non_high_alerts() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    client = httpx.Client(transport=httpx.MockTransport(handler))

    assert not dispatch_alert_webhook(
        "https://hooks.example.test/threatlens",
        make_alert(severity=AlertSeverity.MEDIUM),
        client=client,
    )
    assert calls == []


@pytest.mark.parametrize("url", ["ftp://hooks.example.test/x", "not-a-url", "https://"])
def test_rejects_invalid_webhook_url(url: str) -> None:
    with pytest.raises(ValueError, match="webhook_url"):
        DetectionSettings(webhook_url=url)
