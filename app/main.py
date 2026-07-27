import hmac
import os
import time
import uuid
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Form, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import SQLAlchemyError

from app.api.routes import router
from app.auth import new_csrf_token
from app.config import DetectionSettings
from app.observability import (
    REQUEST_ID_HEADER,
    REQUEST_ID_PATTERN,
    Observability,
    create_logger,
)
from app.storage import ThreatRepository

APP_DIRECTORY = Path(__file__).parent
SESSION_COOKIE_NAME = "threatlens_session"
CSRF_COOKIE_NAME = "threatlens_csrf"
LOGIN_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 300


def create_app(
    repository: ThreatRepository | None = None,
    *,
    detection_settings: DetectionSettings | None = None,
) -> FastAPI:
    database_url = os.getenv("THREATLENS_DATABASE_URL", "sqlite:///threatlens.db")
    threat_repository = repository or ThreatRepository(database_url)
    settings = detection_settings or DetectionSettings.from_environment()
    admin_username = os.getenv("THREATLENS_ADMIN_USERNAME")
    admin_password = os.getenv("THREATLENS_ADMIN_PASSWORD")
    if bool(admin_username) != bool(admin_password):
        raise RuntimeError(
            "THREATLENS_ADMIN_USERNAME and THREATLENS_ADMIN_PASSWORD "
            "must be configured together."
        )
    session_hours = int(os.getenv("THREATLENS_SESSION_HOURS", "12"))
    if session_hours < 1:
        raise ValueError("THREATLENS_SESSION_HOURS must be at least 1.")
    secure_cookies = os.getenv("THREATLENS_SECURE_COOKIES", "false").lower() in {
        "1",
        "true",
        "yes",
    }
    logger = create_logger(os.getenv("THREATLENS_LOG_LEVEL", "INFO"))
    observability = Observability()
    application_version = os.getenv("THREATLENS_VERSION", "dev")

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.repository.initialize()
        if admin_username and admin_password:
            application.state.repository.bootstrap_admin(
                admin_username,
                admin_password,
            )
        try:
            yield
        finally:
            application.state.repository.close()

    application = FastAPI(
        title="ThreatLens",
        description="Security event log analysis and detection API.",
        version=application_version,
        lifespan=lifespan,
    )
    application.state.repository = threat_repository
    application.state.session_cookie_name = SESSION_COOKIE_NAME
    application.state.session_lifetime = timedelta(hours=session_hours)
    application.state.secure_cookies = secure_cookies
    application.state.csrf_cookie_name = CSRF_COOKIE_NAME
    application.state.detection_settings = settings
    application.state.logger = logger
    application.state.observability = observability
    login_failures: dict[str, deque[float]] = defaultdict(deque)
    application.include_router(router)
    application.mount(
        "/static",
        StaticFiles(directory=APP_DIRECTORY / "static"),
        name="static",
    )
    templates = Jinja2Templates(directory=APP_DIRECTORY / "templates")

    @application.middleware("http")
    async def observe_request(request: Request, call_next) -> Response:
        supplied_request_id = request.headers.get(REQUEST_ID_HEADER, "")
        request_id = (
            supplied_request_id
            if REQUEST_ID_PATTERN.fullmatch(supplied_request_id)
            else str(uuid.uuid4())
        )
        request.state.request_id = request_id
        started_at = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration = time.perf_counter() - started_at
            route = _route_name(request)
            observability.record_request(
                method=request.method,
                route=route,
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                duration_seconds=duration,
            )
            if request.url.path == "/api/logs/import":
                observability.record_import_failure(duration)
            logger.exception(
                "request.failed",
                extra=_request_log_fields(
                    request,
                    route,
                    request_id,
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    duration,
                ),
            )
            raise
        duration = time.perf_counter() - started_at
        route = _route_name(request)
        observability.record_request(
            method=request.method,
            route=route,
            status_code=response.status_code,
            duration_seconds=duration,
        )
        if (
            request.url.path == "/api/logs/import"
            and response.status_code >= status.HTTP_400_BAD_REQUEST
        ):
            observability.record_import_failure(duration)
        response.headers[REQUEST_ID_HEADER] = request_id
        logger.info(
            "request.completed",
            extra=_request_log_fields(
                request,
                route,
                request_id,
                response.status_code,
                duration,
            ),
        )
        return response

    @application.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = threat_repository.get_session_user(token) if token else None
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        csrf_token = request.cookies.get(CSRF_COOKIE_NAME) or new_csrf_token()
        response = templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "user": user,
                "csrf_token": csrf_token,
            },
        )
        if CSRF_COOKIE_NAME not in request.cookies:
            _set_csrf_cookie(response, application, csrf_token)
        return response

    @application.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if token and threat_repository.get_session_user(token):
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None},
        )

    @application.get("/account", response_class=HTMLResponse)
    def account_page(request: Request) -> HTMLResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = threat_repository.get_session_user(token) if token else None
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        csrf_token = request.cookies.get(CSRF_COOKIE_NAME) or new_csrf_token()
        response = templates.TemplateResponse(
            request=request,
            name="account.html",
            context={
                "user": user,
                "csrf_token": csrf_token,
            },
        )
        if CSRF_COOKIE_NAME not in request.cookies:
            _set_csrf_cookie(response, application, csrf_token)
        return response

    @application.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(),
        password: str = Form(),
    ) -> HTMLResponse:
        source_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        failures = login_failures[source_ip]
        while failures and failures[0] <= now - LOGIN_WINDOW_SECONDS:
            failures.popleft()
        if len(failures) >= LOGIN_ATTEMPTS:
            threat_repository.record_audit(
                "login.rate_limited",
                target_type="authentication",
                source_ip=source_ip,
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Too many attempts. Try again later."},
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        user = threat_repository.authenticate(username, password)
        if user is None:
            failures.append(now)
            threat_repository.record_audit(
                "login.failed",
                target_type="authentication",
                target_id=username.strip().casefold(),
                source_ip=source_ip,
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid username or password."},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        failures.clear()
        token = threat_repository.create_session(
            user.id,
            lifetime=application.state.session_lifetime,
        )
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            max_age=int(application.state.session_lifetime.total_seconds()),
            httponly=True,
            secure=application.state.secure_cookies,
            samesite="strict",
            path="/",
        )
        _set_csrf_cookie(response, application, new_csrf_token())
        threat_repository.record_audit(
            "login.succeeded",
            actor_id=user.id,
            target_type="authentication",
            target_id=str(user.id),
            source_ip=source_ip,
        )
        return response

    @application.post("/logout")
    def logout(
        request: Request,
        csrf_token: str = Form(default=""),
    ) -> RedirectResponse:
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        if not cookie_csrf or not hmac.compare_digest(cookie_csrf, csrf_token):
            return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = threat_repository.get_session_user(token) if token else None
        if token:
            threat_repository.delete_session(token)
        if user:
            threat_repository.record_audit(
                "logout",
                actor_id=user.id,
                target_type="authentication",
                target_id=str(user.id),
            )
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        response.delete_cookie(CSRF_COOKIE_NAME, path="/")
        return response

    @application.get("/health")
    def health_check() -> dict[str, str]:
        """Return a simple response used to verify that the API is running."""
        return {"status": "ok", "service": "ThreatLens"}

    @application.get("/ready")
    def readiness_check() -> JSONResponse:
        try:
            threat_repository.check_connection()
        except SQLAlchemyError:
            logger.exception("readiness.failed")
            return JSONResponse(
                {"status": "unavailable", "service": "ThreatLens"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return JSONResponse({"status": "ready", "service": "ThreatLens"})

    @application.get("/metrics")
    def metrics() -> Response:
        content, content_type = observability.render()
        return Response(content=content, headers={"Content-Type": content_type})

    return application


def _set_csrf_cookie(
    response: HTMLResponse | RedirectResponse,
    application: FastAPI,
    token: str,
) -> None:
    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        max_age=int(application.state.session_lifetime.total_seconds()),
        httponly=False,
        secure=application.state.secure_cookies,
        samesite="strict",
        path="/",
    )


def _route_name(request: Request) -> str:
    route = request.scope.get("route")
    return getattr(route, "path", request.url.path)


def _request_log_fields(
    request: Request,
    route: str,
    request_id: str,
    status_code: int,
    duration_seconds: float,
) -> dict[str, object]:
    return {
        "request_id": request_id,
        "method": request.method,
        "route": route,
        "status": status_code,
        "duration_ms": round(duration_seconds * 1000, 3),
    }


app = create_app()
