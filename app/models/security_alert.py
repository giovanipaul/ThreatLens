from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AlertType(StrEnum):
    BRUTE_FORCE = "brute_force"


class AlertSeverity(StrEnum):
    MEDIUM = "medium"
    HIGH = "high"


class SecurityAlert(BaseModel):
    """Structured finding produced by a ThreatLens detection rule."""

    model_config = ConfigDict(frozen=True)

    alert_type: AlertType
    severity: AlertSeverity
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    source_ip: IPv4Address | IPv6Address
    started_at: datetime
    ended_at: datetime
    event_count: int = Field(ge=1)
    usernames: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_time_range(self) -> "SecurityAlert":
        if self.ended_at < self.started_at:
            raise ValueError("Alert end time cannot be before its start time.")
        return self

