import os
from dataclasses import dataclass


def _integer_setting(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer.") from error
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


@dataclass(frozen=True)
class DetectionSettings:
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    password_spray_user_threshold: int = 5
    password_spray_window_seconds: int = 600
    suspicious_success_failure_threshold: int = 3
    suspicious_success_window_seconds: int = 600
    max_upload_mb: int = 2
    max_log_lines: int = 50_000

    def __post_init__(self) -> None:
        constraints = {
            "brute_force_threshold": (2, 10_000),
            "brute_force_window_seconds": (1, 86_400),
            "password_spray_user_threshold": (2, 10_000),
            "password_spray_window_seconds": (1, 86_400),
            "suspicious_success_failure_threshold": (1, 10_000),
            "suspicious_success_window_seconds": (1, 86_400),
            "max_upload_mb": (1, 100),
            "max_log_lines": (1, 1_000_000),
        }
        for name, (minimum, maximum) in constraints.items():
            value = getattr(self, name)
            if not minimum <= value <= maximum:
                raise ValueError(
                    f"{name} must be between {minimum} and {maximum}."
                )

    @classmethod
    def from_environment(cls) -> "DetectionSettings":
        return cls(
            brute_force_threshold=_integer_setting(
                "BRUTE_FORCE_THRESHOLD", 5, minimum=2, maximum=10_000
            ),
            brute_force_window_seconds=_integer_setting(
                "BRUTE_FORCE_WINDOW_SECONDS",
                300,
                minimum=1,
                maximum=86_400,
            ),
            password_spray_user_threshold=_integer_setting(
                "PASSWORD_SPRAY_USER_THRESHOLD",
                5,
                minimum=2,
                maximum=10_000,
            ),
            password_spray_window_seconds=_integer_setting(
                "PASSWORD_SPRAY_WINDOW_SECONDS",
                600,
                minimum=1,
                maximum=86_400,
            ),
            suspicious_success_failure_threshold=_integer_setting(
                "SUSPICIOUS_SUCCESS_FAILURE_THRESHOLD",
                3,
                minimum=1,
                maximum=10_000,
            ),
            suspicious_success_window_seconds=_integer_setting(
                "SUSPICIOUS_SUCCESS_WINDOW_SECONDS",
                600,
                minimum=1,
                maximum=86_400,
            ),
            max_upload_mb=_integer_setting(
                "MAX_UPLOAD_MB", 2, minimum=1, maximum=100
            ),
            max_log_lines=_integer_setting(
                "MAX_LOG_LINES", 50_000, minimum=1, maximum=1_000_000
            ),
        )

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024
