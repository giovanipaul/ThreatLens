import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

REQUEST_ID_HEADER = "X-Request-ID"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
LOG_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "taskName",
    "thread",
    "threadName",
}


class JsonFormatter(logging.Formatter):
    """Render application logs as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in LOG_RECORD_FIELDS and not key.startswith("_")
            }
        )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def create_logger(level_name: str) -> logging.Logger:
    normalized_level = level_name.upper()
    levels = logging.getLevelNamesMapping()
    if normalized_level not in levels:
        raise ValueError("THREATLENS_LOG_LEVEL must be a valid logging level.")
    level = levels[normalized_level]
    logger = logging.getLogger("threatlens")
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


class Observability:
    """Own application metrics so each app instance has isolated state."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "threatlens_http_requests_total",
            "HTTP requests handled by ThreatLens.",
            ("method", "route", "status"),
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "threatlens_http_request_duration_seconds",
            "ThreatLens HTTP request duration.",
            ("method", "route"),
            registry=self.registry,
        )
        self.imports = Counter(
            "threatlens_log_imports_total",
            "ThreatLens log imports.",
            ("status",),
            registry=self.registry,
        )
        self.import_events = Counter(
            "threatlens_import_events_total",
            "Events processed by ThreatLens imports.",
            ("result",),
            registry=self.registry,
        )
        self.import_alerts = Counter(
            "threatlens_import_alerts_total",
            "Alerts processed by ThreatLens imports.",
            ("result",),
            registry=self.registry,
        )
        self.import_duration = Histogram(
            "threatlens_import_duration_seconds",
            "ThreatLens log import duration.",
            registry=self.registry,
        )

    def record_request(
        self,
        *,
        method: str,
        route: str,
        status_code: int,
        duration_seconds: float,
    ) -> None:
        self.http_requests.labels(method, route, str(status_code)).inc()
        self.http_duration.labels(method, route).observe(duration_seconds)

    def record_import(
        self,
        *,
        events_parsed: int,
        events_saved: int,
        alerts_generated: int,
        alerts_saved: int,
        duration_seconds: float,
    ) -> None:
        self.imports.labels("success").inc()
        self.import_events.labels("parsed").inc(events_parsed)
        self.import_events.labels("saved").inc(events_saved)
        self.import_alerts.labels("generated").inc(alerts_generated)
        self.import_alerts.labels("saved").inc(alerts_saved)
        self.import_duration.observe(duration_seconds)

    def record_import_failure(self, duration_seconds: float) -> None:
        self.imports.labels("failure").inc()
        self.import_duration.observe(duration_seconds)

    def render(self) -> tuple[bytes, str]:
        return generate_latest(self.registry), CONTENT_TYPE_LATEST
