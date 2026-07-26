from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256

from sqlalchemy import Engine, delete, or_, select
from sqlalchemy.orm import sessionmaker

from app.auth import (
    AlertHistoryEntry,
    AuditEntry,
    AuthenticatedUser,
    UserAccount,
    UserRole,
    hash_password,
    new_session_token,
    session_token_digest,
    utc_now,
    verify_password,
)
from app.models.security_alert import (
    AlertSeverity,
    AlertStatus,
    AlertType,
    ManagedAlert,
    SecurityAlert,
)
from app.models.security_event import AuthenticationResult, SecurityEvent
from app.storage.database import Base, create_database_engine, create_session_factory
from app.storage.records import (
    AlertHistoryRecord,
    AlertRecord,
    AlertStateRecord,
    AuditRecord,
    EventRecord,
    SessionRecord,
    UserRecord,
)


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

    def bootstrap_admin(self, username: str, password: str) -> None:
        normalized_username = self._normalize_username(username)
        with self.sessions.begin() as session:
            existing = session.scalar(
                select(UserRecord).where(UserRecord.username == normalized_username)
            )
            if existing is None:
                session.add(
                    UserRecord(
                        username=normalized_username,
                        password_hash=hash_password(password),
                        role=UserRole.ADMIN.value,
                        active=True,
                        created_at=utc_now(),
                    )
                )

    def create_user(
        self,
        username: str,
        password: str,
        role: UserRole = UserRole.ANALYST,
    ) -> AuthenticatedUser:
        record = UserRecord(
            username=self._normalize_username(username),
            password_hash=hash_password(password),
            role=role.value,
            active=True,
            created_at=utc_now(),
        )
        with self.sessions.begin() as session:
            session.add(record)
        return self._record_to_user(record)

    def authenticate(self, username: str, password: str) -> AuthenticatedUser | None:
        with self.sessions() as session:
            record = session.scalar(
                select(UserRecord).where(
                    UserRecord.username == self._normalize_username(username)
                )
            )
            if (
                record is None
                or not record.active
                or not verify_password(password, record.password_hash)
            ):
                return None
            return self._record_to_user(record)

    def create_session(
        self,
        user_id: int,
        *,
        lifetime: timedelta,
    ) -> str:
        token = new_session_token()
        now = utc_now()
        with self.sessions.begin() as session:
            session.add(
                SessionRecord(
                    token_digest=session_token_digest(token),
                    user_id=user_id,
                    created_at=now,
                    expires_at=now + lifetime,
                )
            )
        return token

    def get_session_user(self, token: str) -> AuthenticatedUser | None:
        now = utc_now()
        with self.sessions.begin() as session:
            session.execute(delete(SessionRecord).where(SessionRecord.expires_at <= now))
            record = session.execute(
                select(UserRecord)
                .join(SessionRecord, SessionRecord.user_id == UserRecord.id)
                .where(
                    SessionRecord.token_digest == session_token_digest(token),
                    SessionRecord.expires_at > now,
                    UserRecord.active.is_(True),
                )
            ).scalar_one_or_none()
            return self._record_to_user(record) if record is not None else None

    def delete_session(self, token: str) -> None:
        with self.sessions.begin() as session:
            session.execute(
                delete(SessionRecord).where(
                    SessionRecord.token_digest == session_token_digest(token)
                )
            )

    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
    ) -> bool:
        new_hash = hash_password(new_password)
        with self.sessions.begin() as session:
            record = session.get(UserRecord, user_id)
            if record is None or not verify_password(
                current_password,
                record.password_hash,
            ):
                return False
            record.password_hash = new_hash
            session.execute(
                delete(SessionRecord).where(SessionRecord.user_id == user_id)
            )
            return True

    def list_users(self) -> list[UserAccount]:
        with self.sessions() as session:
            records = session.scalars(
                select(UserRecord).order_by(UserRecord.username)
            ).all()
            return [self._record_to_account(record) for record in records]

    def update_user(
        self,
        user_id: int,
        *,
        role: UserRole | None = None,
        active: bool | None = None,
    ) -> UserAccount | None:
        with self.sessions.begin() as session:
            record = session.get(UserRecord, user_id)
            if record is None:
                return None
            if role is not None:
                record.role = role.value
            if active is not None:
                record.active = active
                if not active:
                    session.execute(
                        delete(SessionRecord).where(SessionRecord.user_id == user_id)
                    )
            return self._record_to_account(record)

    def revoke_user_sessions(self, user_id: int) -> bool:
        with self.sessions.begin() as session:
            if session.get(UserRecord, user_id) is None:
                return False
            session.execute(
                delete(SessionRecord).where(SessionRecord.user_id == user_id)
            )
            return True

    def record_audit(
        self,
        action: str,
        *,
        actor_id: int | None = None,
        target_type: str,
        target_id: str | None = None,
        source_ip: str | None = None,
        details: dict[str, object] | None = None,
    ) -> None:
        with self.sessions.begin() as session:
            session.add(
                AuditRecord(
                    occurred_at=utc_now(),
                    actor_id=actor_id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    source_ip=source_ip,
                    details=details or {},
                )
            )

    def list_audit_entries(self, limit: int = 100) -> list[AuditEntry]:
        self._validate_limit(limit)
        with self.sessions() as session:
            records = session.scalars(
                select(AuditRecord)
                .order_by(AuditRecord.occurred_at.desc())
                .limit(limit)
            ).all()
            return [
                AuditEntry(
                    id=record.id,
                    occurred_at=record.occurred_at,
                    actor_id=record.actor_id,
                    action=record.action,
                    target_type=record.target_type,
                    target_id=record.target_id,
                    source_ip=record.source_ip,
                    details=record.details,
                )
                for record in records
            ]

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

    def set_alert_status(
        self,
        alert_id: int,
        status: AlertStatus,
        *,
        actor: AuthenticatedUser | None = None,
        note: str | None = None,
    ) -> bool:
        with self.sessions.begin() as session:
            if session.get(AlertRecord, alert_id) is None:
                return False

            state = session.scalar(
                select(AlertStateRecord).where(
                    AlertStateRecord.alert_id == alert_id
                )
            )
            previous_status = AlertStatus(
                state.status if state is not None else AlertStatus.OPEN.value
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
            if actor is not None:
                session.add(
                    AlertHistoryRecord(
                        alert_id=alert_id,
                        actor_id=actor.id,
                        actor_username=actor.username,
                        previous_status=previous_status.value,
                        new_status=status.value,
                        note=note.strip() if note and note.strip() else None,
                        occurred_at=utc_now(),
                    )
                )
            return True

    def list_alert_history(self, alert_id: int) -> list[AlertHistoryEntry] | None:
        with self.sessions() as session:
            if session.get(AlertRecord, alert_id) is None:
                return None
            records = session.scalars(
                select(AlertHistoryRecord)
                .where(AlertHistoryRecord.alert_id == alert_id)
                .order_by(AlertHistoryRecord.occurred_at, AlertHistoryRecord.id)
            ).all()
            return [
                AlertHistoryEntry(
                    id=record.id,
                    alert_id=record.alert_id,
                    actor_id=record.actor_id,
                    actor_username=record.actor_username,
                    previous_status=record.previous_status,
                    new_status=record.new_status,
                    note=record.note,
                    occurred_at=record.occurred_at,
                )
                for record in records
            ]

    @staticmethod
    def _validate_limit(limit: int) -> None:
        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000.")

    @staticmethod
    def _normalize_username(username: str) -> str:
        normalized = username.strip().casefold()
        if not normalized:
            raise ValueError("Username must not be empty.")
        return normalized

    @staticmethod
    def _record_to_user(record: UserRecord) -> AuthenticatedUser:
        return AuthenticatedUser(
            id=record.id,
            username=record.username,
            role=UserRole(record.role),
        )

    @staticmethod
    def _record_to_account(record: UserRecord) -> UserAccount:
        return UserAccount(
            id=record.id,
            username=record.username,
            role=UserRole(record.role),
            active=record.active,
            created_at=record.created_at,
        )

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
