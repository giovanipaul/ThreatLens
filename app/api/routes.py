from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import IPvAnyAddress

from app.api.dependencies import get_repository
from app.detection import (
    BruteForceDetector,
    PasswordSprayDetector,
    SuspiciousSuccessDetector,
)
from app.models.security_alert import (
    AlertSeverity,
    AlertStatus,
    ManagedAlert,
)
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.parsers import LinuxAuthLogParser
from app.schemas import AlertStatusResponse, AlertStatusUpdate, ImportSummary
from app.services import alerts_to_csv, events_to_csv, models_to_json
from app.storage import ThreatRepository

router = APIRouter(prefix="/api")

RepositoryDependency = Annotated[ThreatRepository, Depends(get_repository)]
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_LOG_LINES = 50_000


@router.post(
    "/logs/import",
    response_model=ImportSummary,
    status_code=status.HTTP_201_CREATED,
)
async def import_log(
    repository: RepositoryDependency,
    file: Annotated[UploadFile, File(description="UTF-8 Linux authentication log")],
    year: Annotated[int | None, Query(ge=1970, le=9999)] = None,
) -> ImportSummary:
    contents = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Log file must not exceed 2 MB.",
        )

    try:
        lines = contents.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log file must use UTF-8 encoding.",
        ) from error

    if len(lines) > MAX_LOG_LINES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Log file must not exceed 50,000 lines.",
        )

    events = LinuxAuthLogParser(year=year).parse_lines(lines)
    alerts = [
        *BruteForceDetector().detect(events),
        *PasswordSprayDetector().detect(events),
        *SuspiciousSuccessDetector().detect(events),
    ]

    return ImportSummary(
        filename=file.filename or "uploaded.log",
        lines_received=len(lines),
        events_parsed=len(events),
        events_saved=repository.save_events(events),
        alerts_generated=len(alerts),
        alerts_saved=repository.save_alerts(alerts),
    )


@router.get("/events", response_model=list[SecurityEvent])
def list_events(
    repository: RepositoryDependency,
    result: AuthenticationResult | None = None,
    source_ip: IPvAnyAddress | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[SecurityEvent]:
    return repository.list_events(
        result=result,
        source_ip=str(source_ip) if source_ip is not None else None,
        limit=limit,
    )


@router.get("/alerts", response_model=list[ManagedAlert])
def list_alerts(
    repository: RepositoryDependency,
    severity: AlertSeverity | None = None,
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[ManagedAlert]:
    return repository.list_managed_alerts(
        severity=severity,
        status=status_filter,
        limit=limit,
    )


@router.patch(
    "/alerts/{alert_id}/status",
    response_model=AlertStatusResponse,
)
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    repository: RepositoryDependency,
) -> AlertStatusResponse:
    if not repository.set_alert_status(alert_id, update.status):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )
    return AlertStatusResponse(id=alert_id, status=update.status)


@router.get("/reports/events.csv")
def export_events_csv(
    repository: RepositoryDependency,
    result: AuthenticationResult | None = None,
    source_ip: IPvAnyAddress | None = None,
) -> Response:
    events = repository.list_events(
        result=result,
        source_ip=str(source_ip) if source_ip is not None else None,
        limit=1000,
    )
    return _download_response(
        events_to_csv(events),
        filename="threatlens-events.csv",
        media_type="text/csv",
    )


@router.get("/reports/events.json")
def export_events_json(
    repository: RepositoryDependency,
    result: AuthenticationResult | None = None,
    source_ip: IPvAnyAddress | None = None,
) -> Response:
    events = repository.list_events(
        result=result,
        source_ip=str(source_ip) if source_ip is not None else None,
        limit=1000,
    )
    return _download_response(
        models_to_json(events),
        filename="threatlens-events.json",
        media_type="application/json",
    )


@router.get("/reports/alerts.csv")
def export_alerts_csv(
    repository: RepositoryDependency,
    severity: AlertSeverity | None = None,
) -> Response:
    alerts = repository.list_alerts(severity=severity, limit=1000)
    return _download_response(
        alerts_to_csv(alerts),
        filename="threatlens-alerts.csv",
        media_type="text/csv",
    )


@router.get("/reports/alerts.json")
def export_alerts_json(
    repository: RepositoryDependency,
    severity: AlertSeverity | None = None,
) -> Response:
    alerts = repository.list_alerts(severity=severity, limit=1000)
    return _download_response(
        models_to_json(alerts),
        filename="threatlens-alerts.json",
        media_type="application/json",
    )


def _download_response(
    content: str,
    *,
    filename: str,
    media_type: str,
) -> Response:
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
