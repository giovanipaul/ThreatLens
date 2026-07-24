from datetime import datetime

from sqlalchemy import JSON, Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.storage.database import Base, UTCDateTime


class EventRecord(Base):
    __tablename__ = "security_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    service: Mapped[str] = mapped_column(String(100))
    result: Mapped[str] = mapped_column(String(20), index=True)
    username: Mapped[str] = mapped_column(String(255), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(50))
    invalid_user: Mapped[bool] = mapped_column(Boolean, default=False)
    raw_message: Mapped[str] = mapped_column(Text)


class AlertRecord(Base):
    __tablename__ = "security_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    alert_type: Mapped[str] = mapped_column(String(50), index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    ended_at: Mapped[datetime] = mapped_column(UTCDateTime())
    event_count: Mapped[int] = mapped_column(Integer)
    usernames: Mapped[list[str]] = mapped_column(JSON)
