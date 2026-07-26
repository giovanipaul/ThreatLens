from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import Response
from pydantic import IPvAnyAddress
from sqlalchemy.exc import IntegrityError

from app.api.dependencies import (
    get_current_user,
    get_repository,
    require_admin,
    require_csrf,
)
from app.auth import AuthenticatedUser, UserRole
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
from app.schemas import (
    AlertHistoryResponse,
    AlertStatusResponse,
    AlertStatusUpdate,
    AuditResponse,
    ImportSummary,
    PasswordChange,
    UserCreate,
    UserResponse,
    UserUpdate,
)
from app.services import alerts_to_csv, events_to_csv, models_to_json
from app.storage import ThreatRepository

router = APIRouter(prefix="/api")

RepositoryDependency = Annotated[ThreatRepository, Depends(get_repository)]
UserDependency = Annotated[AuthenticatedUser, Depends(get_current_user)]
AdminDependency = Annotated[AuthenticatedUser, Depends(require_admin)]
CsrfDependency = Annotated[None, Depends(require_csrf)]
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_LOG_LINES = 50_000
ALLOWED_LOG_EXTENSIONS = {".log", ".txt"}


@router.post(
    "/logs/import",
    response_model=ImportSummary,
    status_code=status.HTTP_201_CREATED,
)
async def import_log(
    repository: RepositoryDependency,
    admin: AdminDependency,
    csrf: CsrfDependency,
    file: Annotated[UploadFile, File(description="UTF-8 Linux authentication log")],
    year: Annotated[int | None, Query(ge=1970, le=9999)] = None,
) -> ImportSummary:
    extension = Path(file.filename or "").suffix.lower()
    if extension not in ALLOWED_LOG_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Log file must use a .log or .txt extension.",
        )

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

    summary = ImportSummary(
        filename=file.filename or "uploaded.log",
        lines_received=len(lines),
        events_parsed=len(events),
        events_saved=repository.save_events(events),
        alerts_generated=len(alerts),
        alerts_saved=repository.save_alerts(alerts),
    )
    repository.record_audit(
        "log.imported",
        actor_id=admin.id,
        target_type="log",
        target_id=file.filename,
        details={"events_saved": summary.events_saved},
    )
    return summary


@router.get("/events", response_model=list[SecurityEvent])
def list_events(
    repository: RepositoryDependency,
    user: UserDependency,
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
    user: UserDependency,
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
    user: UserDependency,
    csrf: CsrfDependency,
) -> AlertStatusResponse:
    if not repository.set_alert_status(
        alert_id,
        update.status,
        actor=user,
        note=update.note,
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )
    repository.record_audit(
        "alert.status_changed",
        actor_id=user.id,
        target_type="alert",
        target_id=str(alert_id),
        details={"status": update.status.value, "note_provided": bool(update.note)},
    )
    return AlertStatusResponse(id=alert_id, status=update.status)


@router.get(
    "/alerts/{alert_id}/history",
    response_model=list[AlertHistoryResponse],
)
def list_alert_history(
    alert_id: int,
    repository: RepositoryDependency,
    user: UserDependency,
) -> list[AlertHistoryResponse]:
    history = repository.list_alert_history(alert_id)
    if history is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found.",
        )
    return [AlertHistoryResponse(**vars(entry)) for entry in history]


@router.post("/account/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    update: PasswordChange,
    repository: RepositoryDependency,
    user: UserDependency,
    csrf: CsrfDependency,
) -> Response:
    if not repository.change_password(
        user.id,
        update.current_password,
        update.new_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )
    repository.record_audit(
        "account.password_changed",
        actor_id=user.id,
        target_type="user",
        target_id=str(user.id),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/admin/users", response_model=list[UserResponse])
def list_users(
    repository: RepositoryDependency,
    admin: AdminDependency,
) -> list[UserResponse]:
    return [UserResponse(**vars(user)) for user in repository.list_users()]


@router.post(
    "/admin/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_user(
    create: UserCreate,
    repository: RepositoryDependency,
    admin: AdminDependency,
    csrf: CsrfDependency,
) -> UserResponse:
    try:
        user = repository.create_user(create.username, create.password, create.role)
    except (IntegrityError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists or is invalid.",
        ) from error
    repository.record_audit(
        "user.created",
        actor_id=admin.id,
        target_type="user",
        target_id=str(user.id),
        details={"role": user.role.value},
    )
    account = next(item for item in repository.list_users() if item.id == user.id)
    return UserResponse(**vars(account))


@router.patch("/admin/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    update: UserUpdate,
    repository: RepositoryDependency,
    admin: AdminDependency,
    csrf: CsrfDependency,
) -> UserResponse:
    if user_id == admin.id and (
        update.active is False or update.role == UserRole.ANALYST
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot remove their own access.",
        )
    account = repository.update_user(
        user_id,
        role=update.role,
        active=update.active,
    )
    if account is None:
        raise HTTPException(status_code=404, detail="User not found.")
    repository.record_audit(
        "user.updated",
        actor_id=admin.id,
        target_type="user",
        target_id=str(user_id),
        details=update.model_dump(exclude_none=True, mode="json"),
    )
    return UserResponse(**vars(account))


@router.post(
    "/admin/users/{user_id}/revoke-sessions",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_sessions(
    user_id: int,
    repository: RepositoryDependency,
    admin: AdminDependency,
    csrf: CsrfDependency,
) -> Response:
    if not repository.revoke_user_sessions(user_id):
        raise HTTPException(status_code=404, detail="User not found.")
    repository.record_audit(
        "user.sessions_revoked",
        actor_id=admin.id,
        target_type="user",
        target_id=str(user_id),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/admin/audit", response_model=list[AuditResponse])
def list_audit(
    repository: RepositoryDependency,
    admin: AdminDependency,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[AuditResponse]:
    return [
        AuditResponse(**vars(entry))
        for entry in repository.list_audit_entries(limit)
    ]


@router.get("/reports/events.csv")
def export_events_csv(
    repository: RepositoryDependency,
    user: UserDependency,
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
    user: UserDependency,
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
    user: UserDependency,
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
    user: UserDependency,
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
