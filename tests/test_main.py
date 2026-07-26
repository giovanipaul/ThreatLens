from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import ThreatRepository


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("THREATLENS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", "this is a secure password")
    application = create_app(
        ThreatRepository(f"sqlite:///{tmp_path / 'main.db'}")
    )
    with TestClient(application) as test_client:
        yield test_client


def test_health_check(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "ThreatLens"}


def test_dashboard_requires_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_renders_for_authenticated_admin(client: TestClient) -> None:
    login = client.post(
        "/login",
        data={"username": "admin", "password": "this is a secure password"},
    )
    response = client.get("/")

    assert login.status_code == 200
    assert response.status_code == 200
    assert "ThreatLens" in response.text
    assert "Authentication events" in response.text
    assert "/static/dashboard.js" in response.text
    assert "admin · admin" in response.text
