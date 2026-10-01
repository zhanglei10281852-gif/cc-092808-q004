from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ReviewerQualificationCreate(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    discipline: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=500)
    actor: str = Field(min_length=1, max_length=100)

    @field_validator("reviewer", "discipline")
    @classmethod
    def strip(cls, value: str) -> str:
        return value.strip()


class OpinionCreate(BaseModel):
    opinion_no: str = Field(min_length=3, max_length=60)
    case_id: int = Field(gt=0)
    examination_id: int = Field(gt=0)
    title: str = Field(min_length=2, max_length=200)
    body: str = Field(min_length=1, max_length=200_000)
    cited_specimen_ids: list[int] = Field(default_factory=list, max_length=200)
    cited_observation_ids: list[int] = Field(default_factory=list, max_length=500)
    cited_protocol_id: int | None = Field(default=None, gt=0)
    declaration_note: str = Field(default="", max_length=1000)
    deadline_hours: int = Field(default=72, gt=0, le=24 * 365)
    actor: str = Field(min_length=1, max_length=100)

    @field_validator("opinion_no")
    @classmethod
    def normalize_opinion_no(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("actor", "title")
    @classmethod
    def strip_text(cls, value: str) -> str:
        return value.strip()


class OpinionRevisionCreate(BaseModel):
    body: str = Field(min_length=1, max_length=200_000)
    cited_specimen_ids: list[int] = Field(default_factory=list, max_length=200)
    cited_observation_ids: list[int] = Field(default_factory=list, max_length=500)
    cited_protocol_id: int | None = Field(default=None, gt=0)
    declaration_note: str = Field(default="", max_length=1000)
    change_note: str = Field(min_length=1, max_length=1000)
    actor: str = Field(min_length=1, max_length=100)


class ReviewClaim(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)


class FindingCreate(BaseModel):
    location: str = Field(min_length=1, max_length=500)
    severity: str = Field(pattern="^(minor|major|blocking)$")
    description: str = Field(min_length=2, max_length=2000)


class FindingSubmit(FindingCreate):
    reviewer: str = Field(min_length=1, max_length=100)


class FindingResponse(BaseModel):
    note: str = Field(min_length=1, max_length=2000)
    accept: bool = True
    actor: str = Field(min_length=1, max_length=100)


class ReviewDecision(BaseModel):
    approve: bool
    note: str = Field(default="", max_length=2000)
    reviewer: str = Field(min_length=1, max_length=100)


class ReassignRequest(BaseModel):
    reviewer: str | None = Field(default=None, min_length=1, max_length=100)
    reason: str = Field(min_length=2, max_length=500)
    deadline_hours: int = Field(default=72, gt=0, le=24 * 365)
    actor: str = Field(min_length=1, max_length=100)


class ResubmitRequest(BaseModel):
    change_note: str = Field(default="", max_length=1000)
    deadline_hours: int = Field(default=72, gt=0, le=24 * 365)
    actor: str = Field(min_length=1, max_length=100)


class IssueRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=1000)
    expected_version: int = Field(gt=0)


class TimelineQuery(BaseModel):
    opinion_id: int
