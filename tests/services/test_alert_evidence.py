from datetime import UTC, datetime

from app.models.security_alert import AlertSeverity, AlertType, SecurityAlert
from app.services.alert_evidence import alert_evidence


def test_evidence_excludes_descriptions_and_bounds_untrusted_accounts() -> None:
    alert = SecurityAlert(
        alert_type=AlertType.BRUTE_FORCE,
        severity=AlertSeverity.HIGH,
        title="private title",
        description="private raw log content",
        source_ip="192.0.2.1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
        event_count=30,
        usernames=["x" * 200] + [f"user{i}" for i in range(25)],
    )

    evidence = alert_evidence(alert)

    assert evidence.detection_rule == "brute_force"
    assert evidence.source_ip == "192.0.2.1"
    assert evidence.event_count == 30
    assert len(evidence.targeted_accounts) == 20
    assert len(evidence.targeted_accounts[0]) == 128
    assert evidence.accounts_truncated
    assert "private" not in evidence.model_dump_json()


def test_evidence_identifies_complete_account_list() -> None:
    alert = SecurityAlert(
        alert_type=AlertType.BRUTE_FORCE,
        severity=AlertSeverity.MEDIUM,
        title="alert",
        description="details",
        source_ip="192.0.2.1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        ended_at=datetime(2026, 1, 1, tzinfo=UTC),
        event_count=1,
        usernames=["root"],
    )
    assert not alert_evidence(alert).accounts_truncated
