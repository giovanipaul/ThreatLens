import json
import logging
import sys
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.main import create_app
from app.observability import JsonFormatter, Observability, create_logger
from app.storage import ThreatRepository


@pytest.fixture
def application(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> FastAPI:
    monkeypatch.setenv("THREATLENS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv(
        "THREATLENS_ADMIN_PASSWORD",
        "observability admin password",
    )
    repository = ThreatRepository(f"sqlite:///{tmp_path / 'telemetry.db'}")
    return create_app(repository)


def test_json_formatter_includes_context_and_exception() -> None:
    formatter = JsonFormatter()
    try:
        raise RuntimeError("database unavailable")
    except RuntimeError:
        record = logging.LogRecord(
            name="threatlens",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="request.failed",
            args=(),
            exc_info=sys.exc_info(),
        )
        record.request_id = "request-123"
        payload = json.loads(formatter.format(record))

    assert payload["level"] == "ERROR"
    assert payload["logger"] == "threatlens"
    assert payload["message"] == "request.failed"
    assert payload["request_id"] == "request-123"
    assert "RuntimeError: database unavailable" in payload["exception"]


def test_create_logger_validates_level() -> None:
    logger = create_logger("warning")

    assert logger.level == logging.WARNING
    assert isinstance(logger.handlers[0].formatter, JsonFormatter)
    with pytest.raises(ValueError, match="valid logging level"):
        create_logger("verbose")


def test_request_ids_readiness_and_http_metrics(application: FastAPI) -> None:
    with TestClient(application) as client:
        supplied = client.get("/health", headers={"X-Request-ID": "scan-42"})
        generated = client.get(
            "/ready",
            headers={"X-Request-ID": "invalid request id"},
        )
        metrics = client.get("/metrics")

    assert supplied.status_code == 200
    assert supplied.headers["X-Request-ID"] == "scan-42"
    assert generated.status_code == 200
    assert generated.json() == {"status": "ready", "service": "ThreatLens"}
    uuid.UUID(generated.headers["X-Request-ID"])
    assert metrics.headers["content-type"].startswith("text/plain; version=1.0.0")
    assert (
        'threatlens_http_requests_total{method="GET",route="/health",'
        'status="200"} 1.0'
    ) in metrics.text
    assert (
        'threatlens_http_requests_total{method="GET",route="/ready",'
        'status="200"} 1.0'
    ) in metrics.text


def test_readiness_reports_database_failure(
    application: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_connection() -> None:
        raise SQLAlchemyError("offline")

    monkeypatch.setattr(
        application.state.repository,
        "check_connection",
        fail_connection,
    )
    with TestClient(application, raise_server_exceptions=False) as client:
        response = client.get("/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "unavailable",
        "service": "ThreatLens",
    }


def test_import_metrics_capture_pipeline_results(application: FastAPI) -> None:
    suspicious_log = "\n".join(
        [
            (
                f"Jul 23 21:14:0{second} web-01 sshd[{1800 + second}]: "
                f"Failed password for root from 203.0.113.10 "
                f"port {49210 + second} ssh2"
            )
            for second in range(5)
        ]
    )
    with TestClient(application) as client:
        client.post(
            "/login",
            data={
                "username": "admin",
                "password": "observability admin password",
            },
        )
        client.headers["X-CSRF-Token"] = client.cookies["threatlens_csrf"]
        imported = client.post(
            "/api/logs/import?year=2026",
            files={"file": ("auth.log", suspicious_log, "text/plain")},
        )
        metrics = client.get("/metrics")

    assert imported.status_code == 201
    assert 'threatlens_log_imports_total{status="success"} 1.0' in metrics.text
    assert 'threatlens_import_events_total{result="parsed"} 5.0' in metrics.text
    assert 'threatlens_import_events_total{result="saved"} 5.0' in metrics.text
    assert (
        'threatlens_import_alerts_total{result="generated"} 1.0'
        in metrics.text
    )
    assert 'threatlens_import_alerts_total{result="saved"} 1.0' in metrics.text
    assert "threatlens_import_duration_seconds_count 1.0" in metrics.text


def test_failed_import_is_counted(application: FastAPI) -> None:
    with TestClient(application) as client:
        client.post(
            "/login",
            data={
                "username": "admin",
                "password": "observability admin password",
            },
        )
        client.headers["X-CSRF-Token"] = client.cookies["threatlens_csrf"]
        rejected = client.post(
            "/api/logs/import",
            files={"file": ("auth.csv", "invalid", "text/csv")},
        )
        metrics = client.get("/metrics")

    assert rejected.status_code == 400
    assert 'threatlens_log_imports_total{status="failure"} 1.0' in metrics.text
    assert "threatlens_import_duration_seconds_count 1.0" in metrics.text


def test_observability_records_failed_request() -> None:
    telemetry = Observability()

    telemetry.record_request(
        method="GET",
        route="/failure",
        status_code=500,
        duration_seconds=0.25,
    )
    content, content_type = telemetry.render()
    rendered = content.decode()

    assert content_type.startswith("text/plain; version=1.0.0")
    assert (
        'threatlens_http_requests_total{method="GET",route="/failure",'
        'status="500"} 1.0'
    ) in rendered
    telemetry.record_import_failure(0.5)
    failed_imports, _ = telemetry.render()
    assert (
        'threatlens_log_imports_total{status="failure"} 1.0'
        in failed_imports.decode()
    )
