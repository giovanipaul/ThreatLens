import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import router
from app.storage import ThreatRepository

APP_DIRECTORY = Path(__file__).parent


def create_app(repository: ThreatRepository | None = None) -> FastAPI:
    database_url = os.getenv("THREATLENS_DATABASE_URL", "sqlite:///threatlens.db")
    threat_repository = repository or ThreatRepository(database_url)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.repository.initialize()
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
    application.include_router(router)
    application.mount(
        "/static",
        StaticFiles(directory=APP_DIRECTORY / "static"),
        name="static",
    )
    templates = Jinja2Templates(directory=APP_DIRECTORY / "templates")

    @application.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
        )

    @application.get("/health")
    def health_check() -> dict[str, str]:
        """Return a simple response used to verify that the API is running."""
        return {"status": "ok", "service": "ThreatLens"}

    return application


app = create_app()
