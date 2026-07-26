import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import router
from app.storage import ThreatRepository

APP_DIRECTORY = Path(__file__).parent
SESSION_COOKIE_NAME = "threatlens_session"


def create_app(repository: ThreatRepository | None = None) -> FastAPI:
    database_url = os.getenv("THREATLENS_DATABASE_URL", "sqlite:///threatlens.db")
    threat_repository = repository or ThreatRepository(database_url)
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
        version="0.2.0",
        lifespan=lifespan,
    )
    application.state.repository = threat_repository
    application.state.session_cookie_name = SESSION_COOKIE_NAME
    application.state.session_lifetime = timedelta(hours=session_hours)
    application.state.secure_cookies = secure_cookies
    application.include_router(router)
    application.mount(
        "/static",
        StaticFiles(directory=APP_DIRECTORY / "static"),
        name="static",
    )
    templates = Jinja2Templates(directory=APP_DIRECTORY / "templates")

    @application.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        user = threat_repository.get_session_user(token) if token else None
        if user is None:
            return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={"user": user},
        )

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

    @application.post("/login", response_class=HTMLResponse)
    def login(
        request: Request,
        username: str = Form(),
        password: str = Form(),
    ) -> HTMLResponse:
        user = threat_repository.authenticate(username, password)
        if user is None:
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid username or password."},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
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
        return response

    @application.post("/logout")
    def logout(request: Request) -> RedirectResponse:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if token:
            threat_repository.delete_session(token)
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return response

    @application.get("/health")
    def health_check() -> dict[str, str]:
        """Return a simple response used to verify that the API is running."""
        return {"status": "ok", "service": "ThreatLens"}

    return application


app = create_app()
