from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.storage import ThreatRepository


def create_app(repository: ThreatRepository | None = None) -> FastAPI:
    threat_repository = repository or ThreatRepository()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.repository.initialize()
        yield

    application = FastAPI(
        title="ThreatLens",
        description="Security event log analysis and detection API.",
        version="0.2.0",
        lifespan=lifespan,
    )
    application.state.repository = threat_repository
    application.include_router(router)

    @application.get("/health")
    def health_check() -> dict[str, str]:
        """Return a simple response used to verify that the API is running."""
        return {"status": "ok", "service": "ThreatLens"}

    return application


app = create_app()

