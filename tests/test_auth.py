from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import UserRole, hash_password, verify_password
from app.main import SESSION_COOKIE_NAME, create_app
from app.storage import ThreatRepository

ADMIN_PASSWORD = "correct horse battery staple"


@pytest.fixture
def repository(tmp_path: Path) -> ThreatRepository:
    repo = ThreatRepository(f"sqlite:///{tmp_path / 'auth.db'}")
    repo.initialize()
    try:
        yield repo
    finally:
        repo.close()


def test_scrypt_hashes_are_salted_and_verify() -> None:
    first = hash_password(ADMIN_PASSWORD)
    second = hash_password(ADMIN_PASSWORD)

    assert first.startswith("scrypt$")
    assert first != second
    assert verify_password(ADMIN_PASSWORD, first)
    assert not verify_password("incorrect password", first)
    assert not verify_password(ADMIN_PASSWORD, "not-a-valid-hash")
    assert not verify_password(
        ADMIN_PASSWORD,
        first.replace(f"scrypt${2**14}", f"scrypt${2**15}"),
    )
    assert not verify_password(
        ADMIN_PASSWORD,
        "$".join((*first.split("$")[:-1], "c2hvcnQ=")),
    )


def test_rejects_short_password() -> None:
    with pytest.raises(ValueError, match="at least 12"):
        hash_password("too-short")


def test_users_authenticate_and_sessions_are_revocable(
    repository: ThreatRepository,
) -> None:
    analyst = repository.create_user(
        " Analyst ",
        ADMIN_PASSWORD,
        UserRole.ANALYST,
    )

    assert analyst.username == "analyst"
    assert repository.authenticate("ANALYST", ADMIN_PASSWORD) == analyst
    assert repository.authenticate("analyst", "wrong password") is None
    token = repository.create_session(analyst.id, lifetime=timedelta(hours=1))
    assert repository.get_session_user(token) == analyst
    repository.delete_session(token)
    assert repository.get_session_user(token) is None


def test_expired_session_is_rejected(repository: ThreatRepository) -> None:
    user = repository.create_user("analyst", ADMIN_PASSWORD)
    token = repository.create_session(user.id, lifetime=timedelta(seconds=-1))

    assert repository.get_session_user(token) is None


def test_bootstrap_admin_is_idempotent(repository: ThreatRepository) -> None:
    repository.bootstrap_admin("Admin", ADMIN_PASSWORD)
    repository.bootstrap_admin("admin", "a different secure password")

    user = repository.authenticate("admin", ADMIN_PASSWORD)
    assert user is not None
    assert user.role == UserRole.ADMIN


def make_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> TestClient:
    monkeypatch.setenv("THREATLENS_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("THREATLENS_ADMIN_PASSWORD", ADMIN_PASSWORD)
    return TestClient(
        create_app(ThreatRepository(f"sqlite:///{tmp_path / 'web-auth.db'}"))
    )


def test_login_failure_success_and_logout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        login_page = client.get("/login")
        failure = client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
        )
        success = client.post(
            "/login",
            data={"username": "admin", "password": ADMIN_PASSWORD},
            follow_redirects=False,
        )

        assert login_page.status_code == 200
        assert "Sign in" in login_page.text
        assert failure.status_code == 401
        assert "Invalid username or password" in failure.text
        assert success.status_code == 303
        cookie = success.headers["set-cookie"]
        assert f"{SESSION_COOKIE_NAME}=" in cookie
        assert "HttpOnly" in cookie
        assert "SameSite=strict" in cookie

        client.cookies.update(success.cookies)
        assert client.get("/login", follow_redirects=False).status_code == 303
        logout = client.post(
            "/logout",
            data={"csrf_token": client.cookies["threatlens_csrf"]},
            follow_redirects=False,
        )
        assert logout.status_code == 303
        assert client.get("/", follow_redirects=False).status_code == 303


def test_api_authentication_and_role_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        unauthenticated = client.get("/api/events")
        client.post(
            "/login",
            data={"username": "admin", "password": ADMIN_PASSWORD},
        )
        repository = client.app.state.repository
        repository.create_user("analyst", "analyst secure password", UserRole.ANALYST)
        client.post("/logout")
        client.post(
            "/login",
            data={"username": "analyst", "password": "analyst secure password"},
        )
        readable = client.get("/api/events")
        forbidden = client.post(
            "/api/logs/import",
            files={"file": ("auth.log", "", "text/plain")},
        )

        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["detail"] == "Authentication required."
        assert readable.status_code == 200
        assert forbidden.status_code == 403
        assert forbidden.json()["detail"] == "Administrator access required."
        dashboard = client.get("/")
        assert 'data-role="analyst"' in dashboard.text
        assert 'id="upload-form" class="upload-panel" hidden' in dashboard.text


def test_logout_without_session_is_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        response = client.post("/logout", follow_redirects=False)
        assert response.status_code == 303


def test_requires_complete_bootstrap_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("THREATLENS_ADMIN_USERNAME", "admin")
    monkeypatch.delenv("THREATLENS_ADMIN_PASSWORD", raising=False)

    with pytest.raises(RuntimeError, match="must be configured together"):
        create_app()


def test_validates_session_lifetime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("THREATLENS_ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("THREATLENS_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("THREATLENS_SESSION_HOURS", "0")

    with pytest.raises(ValueError, match="at least 1"):
        create_app()


def authenticate_admin(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/login",
        data={"username": "admin", "password": ADMIN_PASSWORD},
    )
    assert response.status_code == 200
    return {"X-CSRF-Token": client.cookies["threatlens_csrf"]}


def test_csrf_protects_mutations_and_account_page_renders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        headers = authenticate_admin(client)
        rejected = client.post(
            "/api/admin/users",
            json={"username": "new", "password": "a secure new password"},
        )
        page = client.get("/account")

        assert rejected.status_code == 403
        assert rejected.json()["detail"] == "CSRF validation failed."
        assert page.status_code == 200
        assert "Change password" in page.text
        assert "User accounts" in page.text
        assert headers["X-CSRF-Token"] in page.text


def test_existing_session_receives_csrf_cookie_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        repository = client.app.state.repository
        admin = repository.authenticate("admin", ADMIN_PASSWORD)
        assert admin is not None
        token = repository.create_session(admin.id, lifetime=timedelta(hours=1))
        client.cookies.set(SESSION_COOKIE_NAME, token)

        response = client.get("/")

        assert response.status_code == 200
        assert client.cookies.get("threatlens_csrf")


def test_admin_manages_users_sessions_and_audit_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        headers = authenticate_admin(client)
        created = client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "analyst",
                "password": "analyst secure password",
                "role": "analyst",
            },
        )
        user_id = created.json()["id"]
        duplicate = client.post(
            "/api/admin/users",
            headers=headers,
            json={
                "username": "analyst",
                "password": "another secure password",
            },
        )
        updated = client.patch(
            f"/api/admin/users/{user_id}",
            headers=headers,
            json={"role": "admin", "active": False},
        )
        revoked = client.post(
            f"/api/admin/users/{user_id}/revoke-sessions",
            headers=headers,
        )
        users = client.get("/api/admin/users")
        audit = client.get("/api/admin/audit")

        assert created.status_code == 201
        assert duplicate.status_code == 409
        assert updated.status_code == 200
        assert updated.json()["role"] == "admin"
        assert updated.json()["active"] is False
        assert revoked.status_code == 204
        assert len(users.json()) == 2
        actions = {entry["action"] for entry in audit.json()}
        assert {"user.created", "user.updated", "user.sessions_revoked"} <= actions


def test_admin_management_rejects_unsafe_or_missing_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        headers = authenticate_admin(client)
        admin_id = client.get("/api/admin/users").json()[0]["id"]

        self_disable = client.patch(
            f"/api/admin/users/{admin_id}",
            headers=headers,
            json={"active": False},
        )
        missing_update = client.patch(
            "/api/admin/users/999",
            headers=headers,
            json={"active": False},
        )
        missing_revoke = client.post(
            "/api/admin/users/999/revoke-sessions",
            headers=headers,
        )

        assert self_disable.status_code == 400
        assert missing_update.status_code == 404
        assert missing_revoke.status_code == 404


def test_password_change_verifies_current_password_and_revokes_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        headers = authenticate_admin(client)
        wrong = client.post(
            "/api/account/password",
            headers=headers,
            json={
                "current_password": "wrong password",
                "new_password": "a newer secure password",
            },
        )
        changed = client.post(
            "/api/account/password",
            headers=headers,
            json={
                "current_password": ADMIN_PASSWORD,
                "new_password": "a newer secure password",
            },
        )

        assert wrong.status_code == 400
        assert changed.status_code == 204
        assert client.get("/api/events").status_code == 401
        login = client.post(
            "/login",
            data={"username": "admin", "password": "a newer secure password"},
        )
        assert login.status_code == 200


def test_login_rate_limit_and_security_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with make_client(tmp_path, monkeypatch) as client:
        responses = [
            client.post(
                "/login",
                data={"username": "admin", "password": "wrong"},
            )
            for _ in range(6)
        ]

        assert [response.status_code for response in responses] == [
            401,
            401,
            401,
            401,
            401,
            429,
        ]
        entries = client.app.state.repository.list_audit_entries()
        assert entries[0].action == "login.rate_limited"
        assert sum(entry.action == "login.failed" for entry in entries) == 5
