from datetime import datetime

from pydantic import BaseModel, Field

from app.auth import UserRole


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=12, max_length=1024)
    role: UserRole = UserRole.ANALYST


class UserUpdate(BaseModel):
    role: UserRole | None = None
    active: bool | None = None


class UserResponse(BaseModel):
    id: int
    username: str
    role: UserRole
    active: bool
    created_at: datetime


class AuditResponse(BaseModel):
    id: int
    occurred_at: datetime
    actor_id: int | None
    action: str
    target_type: str
    target_id: str | None
    source_ip: str | None
    details: dict[str, object]
