from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.schemas.explanations import GeneratedGuidance
from app.services.alert_evidence import AlertEvidence
from app.storage import ThreatRepository
from app.storage.explanations import (
    cache_guidance,
    cached_guidance,
    evidence_cache_key,
    reserve_provider_call,
)


def test_cache_is_stable_and_separates_model_and_evidence(tmp_path: Path) -> None:
    repository = ThreatRepository(f"sqlite:///{tmp_path / 'cache.db'}")
    repository.initialize()
    evidence = AlertEvidence(
        detection_rule="brute_force", severity="high", source_ip="192.0.2.1",
        started_at="start", ended_at="end", event_count=5,
        targeted_accounts=["root"], accounts_truncated=False,
    )
    key = evidence_cache_key(evidence, "model-a")
    assert key != evidence_cache_key(evidence, "model-b")
    assert key != evidence_cache_key(evidence.model_copy(update={"event_count": 6}), "model-a")
    assert cached_guidance(repository, key) is None
    value = GeneratedGuidance(summary="Review", analyst_checks=["Check events"])
    cache_guidance(repository, key, value)
    cache_guidance(repository, key, value)
    assert cached_guidance(repository, key) == value
    repository.close()


def test_limits_persist_across_repository_instances(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'limits.db'}"
    first, second = ThreatRepository(url), ThreatRepository(url)
    first.initialize()
    user = first.create_user("analyst", "long enough password")
    another = first.create_user("other", "long enough password")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert reserve_provider_call(first, user.id, now=now, daily_limit=2)
    assert not reserve_provider_call(second, user.id, now=now, daily_limit=2)
    assert reserve_provider_call(second, another.id, now=now, daily_limit=2)
    assert not reserve_provider_call(first, user.id, now=now + timedelta(minutes=1), daily_limit=2)
    assert reserve_provider_call(first, user.id, now=now + timedelta(days=1), daily_limit=2)
    with pytest.raises(ValueError):
        reserve_provider_call(first, user.id, now=now, daily_limit=21)
    with pytest.raises(ValueError):
        reserve_provider_call(first, user.id, now=now.replace(tzinfo=None))
    first.close()
    second.close()


def test_concurrent_reservations_cannot_exceed_daily_limit(tmp_path: Path) -> None:
    repository = ThreatRepository(f"sqlite:///{tmp_path / 'concurrent.db'}")
    repository.initialize()
    users = [repository.create_user(f"user{i}", "long enough password") for i in range(5)]
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(
            lambda user: reserve_provider_call(repository, user.id, now=now, daily_limit=2),
            users,
        ))
    assert sum(results) == 2
    repository.close()
