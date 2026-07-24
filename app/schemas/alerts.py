from pydantic import BaseModel

from app.models.security_alert import AlertStatus


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class AlertStatusResponse(BaseModel):
    id: int
    status: AlertStatus

