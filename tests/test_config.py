import pytest

from app.config import DetectionSettings


def test_uses_documented_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    names = [
        "BRUTE_FORCE_THRESHOLD",
        "BRUTE_FORCE_WINDOW_SECONDS",
        "PASSWORD_SPRAY_USER_THRESHOLD",
        "PASSWORD_SPRAY_WINDOW_SECONDS",
        "SUSPICIOUS_SUCCESS_FAILURE_THRESHOLD",
        "SUSPICIOUS_SUCCESS_WINDOW_SECONDS",
        "MAX_UPLOAD_MB",
        "MAX_LOG_LINES",
    ]
    for name in names:
        monkeypatch.delenv(name, raising=False)

    settings = DetectionSettings.from_environment()

    assert settings == DetectionSettings()
    assert settings.max_upload_bytes == 2 * 1024 * 1024


def test_loads_detection_and_upload_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BRUTE_FORCE_THRESHOLD", "8")
    monkeypatch.setenv("BRUTE_FORCE_WINDOW_SECONDS", "120")
    monkeypatch.setenv("PASSWORD_SPRAY_USER_THRESHOLD", "7")
    monkeypatch.setenv("PASSWORD_SPRAY_WINDOW_SECONDS", "240")
    monkeypatch.setenv("SUSPICIOUS_SUCCESS_FAILURE_THRESHOLD", "4")
    monkeypatch.setenv("SUSPICIOUS_SUCCESS_WINDOW_SECONDS", "360")
    monkeypatch.setenv("MAX_UPLOAD_MB", "4")
    monkeypatch.setenv("MAX_LOG_LINES", "10000")

    settings = DetectionSettings.from_environment()

    assert settings.brute_force_threshold == 8
    assert settings.brute_force_window_seconds == 120
    assert settings.password_spray_user_threshold == 7
    assert settings.password_spray_window_seconds == 240
    assert settings.suspicious_success_failure_threshold == 4
    assert settings.suspicious_success_window_seconds == 360
    assert settings.max_upload_mb == 4
    assert settings.max_log_lines == 10_000


def test_rejects_non_integer_environment_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BRUTE_FORCE_THRESHOLD", "many")

    with pytest.raises(
        ValueError,
        match="BRUTE_FORCE_THRESHOLD must be an integer",
    ):
        DetectionSettings.from_environment()


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("BRUTE_FORCE_THRESHOLD", "1", "between 2 and 10000"),
        ("BRUTE_FORCE_WINDOW_SECONDS", "86401", "between 1 and 86400"),
        ("PASSWORD_SPRAY_USER_THRESHOLD", "1", "between 2 and 10000"),
        ("PASSWORD_SPRAY_WINDOW_SECONDS", "0", "between 1 and 86400"),
        (
            "SUSPICIOUS_SUCCESS_FAILURE_THRESHOLD",
            "0",
            "between 1 and 10000",
        ),
        ("SUSPICIOUS_SUCCESS_WINDOW_SECONDS", "-1", "between 1 and 86400"),
        ("MAX_UPLOAD_MB", "101", "between 1 and 100"),
        ("MAX_LOG_LINES", "0", "between 1 and 1000000"),
    ],
)
def test_rejects_out_of_range_environment_values(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
    message: str,
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=message):
        DetectionSettings.from_environment()


def test_rejects_invalid_direct_configuration() -> None:
    with pytest.raises(ValueError, match="brute_force_threshold"):
        DetectionSettings(brute_force_threshold=0)
