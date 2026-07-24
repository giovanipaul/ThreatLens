from fastapi import FastAPI

app = FastAPI(
    title="ThreatLens",
    description="Security event log analysis and detection API.",
    version="0.1.0",
)


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return a simple response used to verify that the API is running."""
    return {"status": "ok", "service": "ThreatLens"}

