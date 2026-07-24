from collections.abc import Iterable
from hashlib import sha256

from sqlalchemy import Engine, or_, select
from sqlalchemy.orm import sessionmaker

from app.models.security_alert import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    ManagedAlert,
    SecurityAlert,
)
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.storage.database import Base, create_database_engine, create_session_factory
from app.storage.records import AlertRecord, AlertStateRecord, EventRecord


class ThreatRepository:
    """Persist and query normalized security events and alerts."""

    def __init__(
        self,
        database_url: str = "sqlite:///threatlens.db",
        *,
        engine: Engine | None = None,
    ) -> None:
        self.engine = engine or create_database_engine(database_url)
        self.sessions: sessionmaker = create_session_factory(self.engine)

    def initialize(self) -> None:
        Base.metadata.create_all(self.engine)

    def close(self) -> None:
        """Release pooled database connections held by the repository."""
        self.engine.dispose()

    def save_events(self, events: Iterable[SecurityEvent]) -> int:
        records = [self._event_to_record(event) for event in events]
        if not records:
            return 0

        fingerprints = [record.fingerprint for record in records]
        with self.sessions.begin() as session:
            existing = set(
                session.scalars(
                    select(EventRecord.fingerprint).where(
                        EventRecord.fingerprint.in_(fingerprints)
                    )
                )
            )
            new_records = [
                record for record in records if record.fingerprint not in existing
            ]
            session.add_all(new_records)
            return len(new_records)

    def save_alerts(self, alerts: Iterable[SecurityAlert]) -> int:
        records = [self._alert_to_record(alert) for alert in alerts]
        if not records:
            return 0

        fingerprints = [record.fingerprint for record in records]
        with self.sessions.begin() as session:
            existing = set(
                session.scalars(
                    select(AlertRecord.fingerprint).where(
                        AlertRecord.fingerprint.in_(fingerprints)
                    )
                )
            )
            new_records = [
                record for record in records if record.fingerprint not in existing
            ]
            session.add_all(new_records)
            return len(new_records)

    def list_events(
        self,
        *,
        result: AuthenticationResult | None = None,
        source_ip: str | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        self._validate_limit(limit)
        statement = select(EventRecord).order_by(EventRecord.timestamp.desc())
        if result is not None:
            statement = statement.where(EventRecord.result == result.value)
        if source_ip is not None:
            statement = statement.where(EventRecord.source_ip == source_ip)

        with self.sessions() as session:
            records = session.scalars(statement.limit(limit)).all()
            return [self._record_to_event(record) for record in records]

    def list_alerts(
        self,
        *,
        severity: AlertSeverity | None = None,
        limit: int = 100,
    ) -> list[SecurityAlert]:
        self._validate_limit(limit)
        statement = select(AlertRecord).order_by(AlertRecord.started_at.desc())
        if severity is not None:
            statement = statement.where(AlertRecord.severity == severity.value)

        with self.sessions() as session:
            records = session.scalars(statement.limit(limit)).all()
            return [self._record_to_alert(record) for record in records]

    def list_managed_alerts(
        self,
        *,
        severity: AlertSeverity | None = None,
        status: AlertStatus | None = None,
        limit: int = 100,
    ) -> list[ManagedAlert]:
        self._validate_limit(limit)
        statement = (
            select(AlertRecord, AlertStateRecord.status)
            .outerjoin(
                AlertStateRecord,
                AlertStateRecord.alert_id == AlertRecord.id,
            )
            .order_by(AlertRecord.started_at.desc())
        )
        if severity is not None:
            statement = statement.where(AlertRecord.severity == severity.value)
        if status == AlertStatus.OPEN:
            statement = statement.where(
                or_(
                    AlertStateRecord.status.is_(None),
                    AlertStateRecord.status == AlertStatus.OPEN.value,
                )
            )
        elif status is not None:
            statement = statement.where(AlertStateRecord.status == status.value)

        with self.sessions() as session:
            rows = session.execute(statement.limit(limit)).all()
            return [
                self._record_to_managed_alert(record, stored_status)
                for record, stored_status in rows
            ]

    def set_alert_status(self, alert_id: int, status: AlertStatus) -> bool:
        with self.sessions.begin() as session:
            if session.get(AlertRecord, alert_id) is None:
                return False

            state = session.scalar(
                select(AlertStateRecord).where(
                    AlertStateRecord.alert_id == alert_id
                )
            )
            if state is None:
                session.add(
                    AlertStateRecord(
                        alert_id=alert_id,
                        status=status.value,
                    )
                )
            else:
                state.status = status.value
            return True

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000.")

    @staticmethod
    def _event_to_record(event: SecurityEvent) -> EventRecord:
        fingerprint = sha256(event.raw_message.encode()).hexdigest()
        return EventRecord(
            fingerprint=fingerprint,
            timestamp=event.timestamp,
            hostname=event.hostname,
            service=event.service,
            result=event.result.value,
            username=event.username,
            source_ip=str(event.source_ip),
            source_port=event.source_port,
            protocol=event.protocol,
            invalid_user=event.invalid_user,
            raw_message=event.raw_message,
        )

    @staticmethod
    def _record_to_event(record: EventRecord) -> SecurityEvent:
        return SecurityEvent(
            timestamp=record.timestamp,
            hostname=record.hostname,
            service=record.service,
            result=AuthenticationResult(record.result),
            username=record.username,
            source_ip=record.source_ip,
            source_port=record.source_port,
            protocol=record.protocol,
            invalid_user=record.invalid_user,
            raw_message=record.raw_message,
        )

    @staticmethod
    def _alert_to_record(alert: SecurityAlert) -> AlertRecord:
        identity = "|".join(
            [
                alert.alert_type.value,
                str(alert.source_ip),
                alert.started_at.isoformat(),
                alert.ended_at.isoformat(),
                str(alert.event_count),
            ]
        )
        return AlertRecord(
            fingerprint=sha256(identity.encode()).hexdigest(),
            alert_type=alert.alert_type.value,
            severity=alert.severity.value,
            title=alert.title,
            description=alert.description,
            source_ip=str(alert.source_ip),
            started_at=alert.started_at,
            ended_at=alert.ended_at,
            event_count=alert.event_count,
            usernames=alert.usernames,
        )

    @staticmethod
    def _record_to_alert(record: AlertRecord) -> SecurityAlert:
        return SecurityAlert(
            alert_type=AlertType(record.alert_type),
            severity=AlertSeverity(record.severity),
            title=record.title,
            description=record.description,
            source_ip=record.source_ip,
            started_at=record.started_at,
            ended_at=record.ended_at,
            event_count=record.event_count,
            usernames=record.usernames,
        )

    @staticmethod
    def _record_to_managed_alert(
        record: AlertRecord,
        stored_status: str | None,
    ) -> ManagedAlert:
        alert = ThreatRepository._record_to_alert(record)
        return ManagedAlert(
            **alert.model_dump(),
            id=record.id,
            status=AlertStatus(stored_status or AlertStatus.OPEN.value),
        )
