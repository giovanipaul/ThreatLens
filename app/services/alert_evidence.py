"""Select the minimum alert evidence suitable for external analysis."""

from pydantic import BaseModel, ConfigDict, Field

from app.models.security_alert import SecurityAlert


class AlertEvidence(BaseModel):
    """A bounded snapshot; all string values remain untrusted data."""

    model_config = ConfigDict(frozen=True)

    detection_rule: str
    severity: str
    source_ip: str
    started_at: str
    ended_at: str
    event_count: int
    targeted_accounts: list[str] = Field(max_length=20)
    accounts_truncated: bool


def alert_evidence(alert: SecurityAlert) -> AlertEvidence:
    """Exclude raw log lines, free-text descriptions and session data."""
    return AlertEvidence(
        detection_rule=alert.alert_type.value,
        severity=alert.severity.value,
        source_ip=str(alert.source_ip),
        started_at=alert.started_at.isoformat(),
        ended_at=alert.ended_at.isoformat(),
        event_count=alert.event_count,
        targeted_accounts=[name[:128] for name in alert.usernames[:20]],
        accounts_truncated=len(alert.usernames) > 20
        or any(len(name) > 128 for name in alert.usernames[:20]),
    )
