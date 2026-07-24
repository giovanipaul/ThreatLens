from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import IPvAnyAddress

from app.api.dependencies import get_repository
from app.detection import BruteForceDetector
from app.models.security_alert import AlertSeverity, SecurityAlert
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.parsers import LinuxAuthLogParser
from app.schemas.imports import ImportSummary
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
    alerts = BruteForceDetector().detect(events)

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


@router.get("/alerts", response_model=list[SecurityAlert])
def list_alerts(
    repository: RepositoryDependency,
    severity: AlertSeverity | None = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[SecurityAlert]:
    return repository.list_alerts(severity=severity, limit=limit)

