"""Persistent explanation caching and bounded provider-call reservations."""

import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy.exc import IntegrityError

from app.schemas.explanations import GeneratedGuidance
from app.services.alert_evidence import AlertEvidence
from app.storage.records import ExplanationAttemptRecord, ExplanationCacheRecord
from app.storage.repository import ThreatRepository


def evidence_cache_key(evidence: AlertEvidence, model: str) -> str:
    payload = {"version": 1, "model": model, "evidence": evidence.model_dump(mode="json")}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def cached_guidance(repository: ThreatRepository, cache_key: str) -> GeneratedGuidance | None:
    with repository.sessions() as session:
        record = session.get(ExplanationCacheRecord, cache_key)
        return GeneratedGuidance.model_validate(record.guidance) if record else None


def cache_guidance(repository: ThreatRepository, cache_key: str, guidance: GeneratedGuidance) -> None:
    try:
        with repository.sessions.begin() as session:
            session.add(ExplanationCacheRecord(
                cache_key=cache_key, guidance=guidance.model_dump(), created_at=datetime.now(UTC)
            ))
    except IntegrityError:
        # Another request stored the same immutable input first.
        if cached_guidance(repository, cache_key) is None:
            raise


def reserve_provider_call(
    repository: ThreatRepository, user_id: int, *, now: datetime | None = None, daily_limit: int = 20
) -> bool:
    """Atomically reserve one of 20 daily calls and one call per user per minute.

    Attempts remain counted on provider failure because a timed-out request may
    still be billed. Unique constraints enforce limits across workers.
    """
    if not 1 <= daily_limit <= 20:
        raise ValueError("Daily limit must be between 1 and 20.")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError("A timezone-aware time is required.")
    now = now.astimezone(UTC)
    day = now.date().isoformat()
    window = int(now.timestamp()) // 60
    for slot in range(daily_limit):
        try:
            with repository.sessions.begin() as session:
                session.add(ExplanationAttemptRecord(
                    day=day, slot=slot, user_id=user_id, window=window, created_at=now
                ))
                session.flush()
            return True
        except IntegrityError:
            continue
    return False
