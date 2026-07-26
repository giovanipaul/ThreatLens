from datetime import datetime

from pydantic import BaseModel, Field

from app.models.security_alert import AlertStatus


class AlertStatusUpdate(BaseModel):
    status: AlertStatus
    note: str | None = Field(default=None, max_length=2000)


class AlertStatusResponse(BaseModel):
    id: int
    status: AlertStatus


class AlertHistoryResponse(BaseModel):
    id: int
    alert_id: int
    actor_id: int
    actor_username: str
    previous_status: AlertStatus
    new_status: AlertStatus
    note: str | None
    occurred_at: datetime
