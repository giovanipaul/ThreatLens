import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_KEY_LENGTH = 32
SALT_LENGTH = 16
SESSION_TOKEN_BYTES = 32
CSRF_TOKEN_BYTES = 32


class UserRole(StrEnum):
    ANALYST = "analyst"
    ADMIN = "admin"


@dataclass(frozen=True)
class AuthenticatedUser:
    id: int
    username: str
    role: UserRole


@dataclass(frozen=True)
class UserAccount:
    id: int
    username: str
    role: UserRole
    active: bool
    created_at: datetime


@dataclass(frozen=True)
class AuditEntry:
    id: int
    occurred_at: datetime
    actor_id: int | None
    action: str
    target_type: str
    target_id: str | None
    source_ip: str | None
    details: dict[str, object]


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters.")
    salt = secrets.token_bytes(SALT_LENGTH)
    derived_key = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_KEY_LENGTH,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode(),
            base64.urlsafe_b64encode(derived_key).decode(),
        )
    )


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt, expected = encoded_hash.split("$")
        if (
            algorithm != "scrypt"
            or int(n) != SCRYPT_N
            or int(r) != SCRYPT_R
            or int(p) != SCRYPT_P
        ):
            return False
        decoded_expected = base64.urlsafe_b64decode(expected)
        if len(decoded_expected) != SCRYPT_KEY_LENGTH:
            return False
        derived_key = hashlib.scrypt(
            password.encode(),
            salt=base64.urlsafe_b64decode(salt),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=SCRYPT_KEY_LENGTH,
        )
        return hmac.compare_digest(derived_key, decoded_expected)
    except (ValueError, TypeError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def new_csrf_token() -> str:
    return secrets.token_urlsafe(CSRF_TOKEN_BYTES)


def session_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def utc_now() -> datetime:
    return datetime.now(UTC)
