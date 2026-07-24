from pydantic import BaseModel, Field


class ImportSummary(BaseModel):
    filename: str
    lines_received: int = Field(ge=0)
    events_parsed: int = Field(ge=0)
    events_saved: int = Field(ge=0)
    alerts_generated: int = Field(ge=0)
    alerts_saved: int = Field(ge=0)

