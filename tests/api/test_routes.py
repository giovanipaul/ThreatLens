from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import ThreatRepository


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    repository = ThreatRepository(f"sqlite:///{tmp_path / 'api.db'}")
    application = create_app(repository)
    with TestClient(application) as test_client:
        yield test_client


def suspicious_log() -> str:
    return "\n".join(
        [
            (
                f"Jul 23 21:14:0{second} web-01 sshd[{1800 + second}]: "
                f"Failed password for root from 203.0.113.10 "
                f"port {49210 + second} ssh2"
            )
            for second in range(5)
        ]
    )


def test_imports_log_and_generates_alert(client: TestClient) -> None:
    response = client.post(
        "/api/logs/import?year=2026",
        files={"file": ("auth.log", suspicious_log(), "text/plain")},
    )

    assert response.status_code == 201
    assert response.json() == {
        "filename": "auth.log",
        "lines_received": 5,
        "events_parsed": 5,
        "events_saved": 5,
        "alerts_generated": 1,
        "alerts_saved": 1,
    }


def test_reimport_does_not_duplicate_records(client: TestClient) -> None:
    upload = {"file": ("auth.log", suspicious_log(), "text/plain")}

    first = client.post("/api/logs/import?year=2026", files=upload)
    second = client.post("/api/logs/import?year=2026", files=upload)

    assert first.status_code == 201
    assert second.status_code == 201
    assert second.json()["events_saved"] == 0
    assert second.json()["alerts_saved"] == 0


def test_queries_events_and_alerts(client: TestClient) -> None:
    client.post(
        "/api/logs/import?year=2026",
        files={"file": ("auth.log", suspicious_log(), "text/plain")},
    )

    events = client.get(
        "/api/events",
        params={"result": "failure", "source_ip": "203.0.113.10"},
    )
    alerts = client.get("/api/alerts", params={"severity": "medium"})

    assert events.status_code == 200
    assert len(events.json()) == 5
    assert alerts.status_code == 200
    assert len(alerts.json()) == 1
    assert alerts.json()[0]["event_count"] == 5


def test_rejects_non_utf8_upload(client: TestClient) -> None:
    response = client.post(
        "/api/logs/import",
        files={"file": ("auth.log", b"\xff\xfe", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Log file must use UTF-8 encoding."


def test_validates_query_parameters(client: TestClient) -> None:
    invalid_ip = client.get("/api/events", params={"source_ip": "not-an-ip"})
    invalid_limit = client.get("/api/alerts", params={"limit": 0})

    assert invalid_ip.status_code == 422
    assert invalid_limit.status_code == 422


@pytest.mark.parametrize(
    ("endpoint", "media_type", "filename"),
    [
        ("/api/reports/events.csv", "text/csv", "threatlens-events.csv"),
        (
            "/api/reports/events.json",
            "application/json",
            "threatlens-events.json",
        ),
        ("/api/reports/alerts.csv", "text/csv", "threatlens-alerts.csv"),
        (
            "/api/reports/alerts.json",
            "application/json",
            "threatlens-alerts.json",
        ),
    ],
)
def test_downloads_reports(
    client: TestClient,
    endpoint: str,
    media_type: str,
    filename: str,
) -> None:
    client.post(
        "/api/logs/import?year=2026",
        files={"file": ("auth.log", suspicious_log(), "text/plain")},
    )

    response = client.get(endpoint)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    assert filename in response.headers["content-disposition"]
