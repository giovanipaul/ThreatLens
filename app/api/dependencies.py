import hmac
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from app.auth import AuthenticatedUser, UserRole
from app.config import DetectionSettings
from app.storage import ThreatRepository


def get_repository(request: Request) -> ThreatRepository:
    return request.app.state.repository


def get_detection_settings(request: Request) -> DetectionSettings:
    return request.app.state.detection_settings


def get_current_user(
    request: Request,
    repository: Annotated[ThreatRepository, Depends(get_repository)],
) -> AuthenticatedUser:
    token = request.cookies.get(request.app.state.session_cookie_name)
    user = repository.get_session_user(token) if token else None
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )
    return user


def require_admin(
    user: Annotated[AuthenticatedUser, Depends(get_current_user)],
) -> AuthenticatedUser:
    if user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required.",
        )
    return user


def require_csrf(request: Request) -> None:
    cookie_token = request.cookies.get(request.app.state.csrf_cookie_name)
    header_token = request.headers.get("X-CSRF-Token")
    if (
        not cookie_token
        or not header_token
        or not hmac.compare_digest(cookie_token, header_token)
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )
