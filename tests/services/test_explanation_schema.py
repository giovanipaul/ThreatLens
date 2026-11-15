import pytest
from pydantic import ValidationError

from app.schemas.explanations import AlertExplanation, GeneratedGuidance
from app.services.alert_evidence import AlertEvidence


def test_explanation_contains_application_warning() -> None:
    evidence = AlertEvidence(detection_rule="brute_force", severity="high", source_ip="192.0.2.1", started_at="start", ended_at="end", event_count=5, targeted_accounts=["root"], accounts_truncated=False)
    explanation = AlertExplanation(summary="A pattern occurred.", analyst_checks=["Review events."], evidence=evidence, cached=False)
    assert explanation.disclaimer == "AI-generated guidance. Verify against the source events."


@pytest.mark.parametrize(
    "content",
    [
        {"summary": " ", "analyst_checks": ["Review events."]},
        {"summary": "x", "analyst_checks": []},
        {"summary": "x", "analyst_checks": ["check"] * 6},
        {"summary": "x" * 1201, "analyst_checks": ["check"]},
        {"summary": "x", "analyst_checks": ["check"], "command": "run"},
    ],
)
def test_rejects_invalid_model_output(content: dict) -> None:
    with pytest.raises(ValidationError):
        GeneratedGuidance.model_validate(content)
