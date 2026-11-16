from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import ThreatRepository


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
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


def test_public_demo_is_static_and_does_not_grant_access(client: TestClient) -> None:
    response = client.get("/demo")

    assert response.status_code == 200
    assert "Read-only sample preview" in response.text
    assert "isolated from the live database" in response.text
    assert "scroll horizontally to see all columns" in response.text
    assert 'aria-describedby="demo-table-hint"' in response.text
    assert 'src="http://testserver/static/demo.js"' in response.text
    assert response.text.count('data-result="failure"') == 6
    assert response.text.count('data-result="success"') == 2
    assert not response.cookies
    assert client.get("/api/events").status_code == 401
    assert client.get("/account", follow_redirects=False).headers["location"] == "/login"
    assert client.post("/demo").status_code == 405


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


def test_exposes_configured_application_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("THREATLENS_VERSION", "v1.2.3")
    application = create_app(
        ThreatRepository(f"sqlite:///{tmp_path / 'version.db'}")
    )

    assert application.version == "v1.2.3"
