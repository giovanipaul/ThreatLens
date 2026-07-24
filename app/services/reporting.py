import csv
import json
from io import StringIO

from pydantic import BaseModel

from app.models.security_alert import SecurityAlert
from app.models.security_event import SecurityEvent


def events_to_csv(events: list[SecurityEvent]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "timestamp",
            "result",
            "username",
            "source_ip",
            "source_port",
            "hostname",
            "service",
            "protocol",
            "invalid_user",
        ]
    )
    for event in events:
        writer.writerow(
            [
                event.timestamp.isoformat(),
                event.result.value,
                event.username,
                str(event.source_ip),
                event.source_port,
                event.hostname,
                event.service,
                event.protocol,
                event.invalid_user,
            ]
        )
    return output.getvalue()


def alerts_to_csv(alerts: list[SecurityAlert]) -> str:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "started_at",
            "ended_at",
            "severity",
            "alert_type",
            "title",
            "source_ip",
            "event_count",
            "usernames",
            "description",
        ]
    )
    for alert in alerts:
        writer.writerow(
            [
                alert.started_at.isoformat(),
                alert.ended_at.isoformat(),
                alert.severity.value,
                alert.alert_type.value,
                alert.title,
                str(alert.source_ip),
                alert.event_count,
                "; ".join(alert.usernames),
                alert.description,
            ]
        )
    return output.getvalue()


def models_to_json(models: list[BaseModel]) -> str:
    payload = [model.model_dump(mode="json") for model in models]
    return json.dumps(payload, indent=2)

