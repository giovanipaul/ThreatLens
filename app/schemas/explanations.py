"""Validated, display-safe structure for model-generated alert guidance."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.services.alert_evidence import AlertEvidence

GuidanceText = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1200)
]


class GeneratedGuidance(BaseModel):
    """Only model-authored content; evidence and disclaimer come from the app."""

    model_config = ConfigDict(extra="forbid")

    summary: GuidanceText
    analyst_checks: list[GuidanceText] = Field(min_length=1, max_length=5)


class AlertExplanation(GeneratedGuidance):
    """Response contract, including a mandatory application-owned warning."""

    disclaimer: Literal["AI-generated guidance. Verify against the source events."] = (
        "AI-generated guidance. Verify against the source events."
    )
    evidence: AlertEvidence
    cached: bool
