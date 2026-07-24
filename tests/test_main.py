from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "ThreatLens"}


def test_dashboard_renders() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "ThreatLens" in response.text
    assert "Authentication events" in response.text
    assert "/static/dashboard.js" in response.text
