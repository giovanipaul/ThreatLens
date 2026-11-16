from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import UserRole
from app.main import create_app
from app.schemas.explanations import GeneratedGuidance
from app.services.explanation_provider import ExplanationProviderError
from app.storage import ThreatRepository
from tests.api.test_routes import suspicious_log


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("THREATLENS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", "correct horse battery staple")
    monkeypatch.delenv("THREATLENS_OPENAI_API_KEY", raising=False)
    repository = ThreatRepository(f"sqlite:///{tmp_path / 'explanations.db'}")
    with TestClient(create_app(repository)) as client:
        client.post("/login", data={"username": "admin", "password": "correct horse battery staple"})
        client.headers["X-CSRF-Token"] = client.cookies["threatlens_csrf"]
        client.post("/api/logs/import?year=2026", files={"file": ("auth.log", suspicious_log(), "text/plain")})
        yield client


def test_disabled_and_missing_alert(client, monkeypatch):
    assert client.post("/api/alerts/1/explanation").status_code == 503
    monkeypatch.setenv("THREATLENS_OPENAI_API_KEY", "test-key")
    assert client.post("/api/alerts/999/explanation").status_code == 404


def test_authentication_csrf_and_cached_success(client, monkeypatch):
    monkeypatch.setenv("THREATLENS_OPENAI_API_KEY", "test-key")
    calls = []
    def fake_provider(evidence, **kwargs):
        calls.append(evidence)
        return GeneratedGuidance(summary="Repeated failures", analyst_checks=["Review events"])
    monkeypatch.setattr("app.api.routes.generate_guidance", fake_provider)
    assert client.post("/api/alerts/1/explanation", headers={"X-CSRF-Token": "wrong"}).status_code == 403
    first = client.post("/api/alerts/1/explanation")
    second = client.post("/api/alerts/1/explanation")
    assert first.status_code == second.status_code == 200
    assert first.json()["cached"] is False
    assert second.json()["cached"] is True
    assert first.json()["evidence"]["event_count"] == 5
    assert "AI-generated" in first.json()["disclaimer"]
    assert len(calls) == 1
    entries = client.app.state.repository.list_audit_entries()
    assert {e.action for e in entries} >= {"explanation.requested", "explanation.viewed"}
    client.cookies.clear()
    assert client.post("/api/alerts/1/explanation").status_code == 401


def test_provider_failure_is_audited_and_rate_limited(client, monkeypatch):
    monkeypatch.setenv("THREATLENS_OPENAI_API_KEY", "test-key")
    def fail(*args, **kwargs):
        raise ExplanationProviderError("secret provider detail")
    monkeypatch.setattr("app.api.routes.generate_guidance", fail)
    response = client.post("/api/alerts/1/explanation")
    assert response.status_code == 502
    assert "secret" not in response.text
    assert client.post("/api/alerts/1/explanation").status_code == 429
    assert "explanation.failed" in {e.action for e in client.app.state.repository.list_audit_entries()}


def test_analyst_can_request_explanation(client, monkeypatch):
    monkeypatch.setenv("THREATLENS_OPENAI_API_KEY", "test-key")
    monkeypatch.setattr("app.api.routes.generate_guidance", lambda *args, **kwargs: GeneratedGuidance(summary="Review", analyst_checks=["Check"]))
    repo = client.app.state.repository
    repo.create_user("analyst", "analyst password long", UserRole.ANALYST)
    client.post("/login", data={"username": "analyst", "password": "analyst password long"})
    client.headers["X-CSRF-Token"] = client.cookies["threatlens_csrf"]
    assert client.post("/api/alerts/1/explanation").status_code == 200
