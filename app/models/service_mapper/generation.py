"""Checked AI answer shapes and the mapper's persisted dependency data."""

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.constants import MapperMessage


class ProposedDependency(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(min_length=2, max_length=255)
    catalog_service_id: int | None = Field(default=None, gt=0)
    sector: str | None = Field(default=None, max_length=255)
    subsector: str | None = Field(default=None, max_length=255)
    dependency_reason: str = Field(min_length=20, max_length=800)
    applicability: str | None = Field(default=None, max_length=500)

    @field_validator("service_name", "dependency_reason")
    @classmethod
    def required_text(cls, value: str) -> str:
        value = " ".join(value.split())
        if not value:
            raise ValueError(MapperMessage.REQUIRED_VALUE_BLANK)
        return value


class GeneratedAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operational_context: str = Field(min_length=30, max_length=1_500)
    upstream_services: list[ProposedDependency] = Field(max_length=200)
    downstream_services: list[ProposedDependency] = Field(max_length=200)


@dataclass(frozen=True)
class ResolvedDependency:
    identity: str
    service_id: int | None
    service_name: str
    sector: str | None
    subsector: str | None
    ai_suggested: bool
    dependency_reason: str
    applicability: str | None
    rank: int
