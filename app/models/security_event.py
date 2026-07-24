from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field


class AuthenticationResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class SecurityEvent(BaseModel):
    """Normalized authentication event produced from a raw log entry."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    hostname: str = Field(min_length=1)
    service: str = Field(min_length=1)
    result: AuthenticationResult
    username: str = Field(min_length=1)
    source_ip: IPv4Address | IPv6Address
    source_port: int = Field(ge=1, le=65535)
    protocol: str = Field(min_length=1)
    invalid_user: bool = False
    raw_message: str = Field(min_length=1)

