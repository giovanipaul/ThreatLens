import csv
import json
from datetime import UTC, datetime
from io import StringIO

from app.detection import BruteForceDetector
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.services import alerts_to_csv, events_to_csv, models_to_json


def make_events() -> list[SecurityEvent]:
    return [
        SecurityEvent(
            timestamp=datetime(2026, 7, 23, 21, minute, tzinfo=UTC),
            hostname="web-01",
            service="sshd",
            result=AuthenticationResult.FAILURE,
            username="root",
            source_ip="203.0.113.10",
            source_port=49211 + minute,
            protocol="password",
            raw_message=f"event-{minute}",
        )
        for minute in range(5)
    ]


def test_exports_events_as_csv() -> None:
    rows = list(csv.DictReader(StringIO(events_to_csv(make_events()))))

    assert len(rows) == 5
    assert rows[0]["result"] == "failure"
    assert rows[0]["source_ip"] == "203.0.113.10"


def test_exports_alerts_as_csv() -> None:
    alert = BruteForceDetector().detect(make_events())[0]

    rows = list(csv.DictReader(StringIO(alerts_to_csv([alert]))))

    assert len(rows) == 1
    assert rows[0]["severity"] == "medium"
    assert rows[0]["event_count"] == "5"


def test_exports_models_as_json() -> None:
    payload = json.loads(models_to_json(make_events()))

    assert len(payload) == 5
    assert payload[0]["timestamp"] == "2026-07-23T21:00:00Z"
    assert payload[0]["source_ip"] == "203.0.113.10"

