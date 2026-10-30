"""Public Service Mapper request and response contract."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import (
    AbandonReason,
    AiOutage,
    MapperDecisionFailure,
    MapperLimits,
    MapperMessage,
    MappingOverall,
    Review,
    Status,
)
from app.models.jobs.views import RetryNotice


class CreateMappingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(min_length=1, max_length=255)
    service_description: str = Field(min_length=1, max_length=4_000)
    sector: str = Field(min_length=1, max_length=255, validation_alias=AliasChoices("sector", "sector_name"))
    subsector: str = Field(
        min_length=1, max_length=255, validation_alias=AliasChoices("subsector", "sub_sector_name")
    )
    entity_names: list[str] = Field(min_length=1, max_length=20)

    @field_validator("service_name", "service_description", "sector", "subsector")
    @classmethod
    def strip_required_text(cls, value: str) -> str:
        stripped = " ".join(value.split())
        if not stripped:
            raise ValueError(MapperMessage.REQUIRED_VALUE_BLANK)
        return stripped

    @field_validator("entity_names")
    @classmethod
    def check_entities(cls, values: list[str]) -> list[str]:
        names = [" ".join(name.split()) for name in values]
        if any(not name or len(name) > 255 for name in names):
            raise ValueError(MapperMessage.ENTITY_NAME_INVALID)
        if len({name.casefold() for name in names}) != len(names):
            raise ValueError(MapperMessage.ENTITY_NAMES_REPEATED)
        return names


class SelectedService(BaseModel):
    service_id: int | None = None
    service_name: str
    service_description: str
    sector: str
    subsector: str
    entity_names: list[str]
    operational_context: str | None = None


class MappingAccepted(BaseModel):
    mapping_id: str
    status: Status
    generation: int


class ServiceRef(BaseModel):
    service_id: int
    name: str
    sector: str | None
    sub_sector: str | None


class EntityServices(BaseModel):
    entity_id: int
    services: list[ServiceRef]


class MappingError(BaseModel):
    code: str
    message: str
    # The AI outage that failed it: ai_down, ai_unreachable, ai_busy, ai_timed_out; job_abandoned: abandoned,
    # never_started (AbandonReason); None for any other.
    reason: AiOutage | AbandonReason | None = None


class RelationshipCounts(BaseModel):
    """The mapping's relationships, one per direction; a run going on adds to them when it ends."""

    total: int
    accepted: int
    rejected: int
    pending: int


class MappingTimings(BaseModel):
    """The latest run's seconds per activity, once it is done."""

    catalog: float | None = None  # reading the onboarding catalog
    services: float | None = None  # finding the upstream and downstream services: ranking, the AI, matching


class MappingProgress(BaseModel):
    overall: MappingOverall
    relationships: RelationshipCounts
    timings: MappingTimings = MappingTimings()


class MappingStatus(BaseModel):
    """GET .../status, and every mapping.updated event (one model, so they can never differ)."""

    mapping_id: str
    entity_id: int
    user_id: str | None
    status: Status
    generation: int  # the latest run: 1 for the first, one more for each Generate again or Regenerate
    generations_done: int  # runs that finished; a failed one does not count
    max_generations: int  # SERVICE_MAPPER_MAX_GENERATIONS: the most runs, the first included (0: no limit)
    progress: MappingProgress
    retrying: RetryNotice | None = None  # waiting out an AI or store outage: why, which try comes when
    error: MappingError | None = None  # once failed
    created_at: datetime
    updated_at: datetime


class DependencyService(BaseModel):
    dependency_id: str
    service_id: int | None
    service_name: str
    sector: str | None
    subsector: str | None
    dependency_reason: str
    applicability: str | None
    ai_suggested: bool
    generation: int | None = None  # the run that found it (None: found before runs were counted)
    isAccepted: bool | None = None
    accepted_datetime: datetime | None = None
    accepted_by: str | None = None


class MappingSummary(BaseModel):
    unique_services: int
    upstream_count: int
    downstream_count: int
    max_upstream: int
    max_downstream: int


class MappingView(BaseModel):
    mapping_id: str
    status: Status
    generation: int  # the latest run: 1 for the first, one more for each Generate again or Regenerate
    generations_done: int  # runs that finished; a failed one does not count
    max_generations: int  # SERVICE_MAPPER_MAX_GENERATIONS: the most runs, the first included (0: no limit)
    upstream_services: list[DependencyService]
    downstream_services: list[DependencyService]
    summary: MappingSummary
    error: MappingError | None = None
    retrying: RetryNotice | None = None  # waiting out an AI or store outage: why, which try comes when
    created_at: datetime
    updated_at: datetime


class MappingListItem(BaseModel):
    mapping_id: str
    status: Status
    generation: int  # the latest run: 1 for the first, one more for each Generate again or Regenerate
    generations_done: int  # runs that finished; a failed one does not count
    max_generations: int  # SERVICE_MAPPER_MAX_GENERATIONS: the most runs, the first included (0: no limit)
    selected_service: SelectedService
    created_at: datetime
    updated_at: datetime


class MappingList(BaseModel):
    items: list[MappingListItem]
    total: int


_DependencyId = Annotated[str, Field(max_length=Review.MAX_ID_CHARS)]


class DependencyDecisionRequest(BaseModel):
    """The relationships to decide, by dependency_id; either list may be null, empty or hold only blanks."""

    model_config = ConfigDict(extra="forbid")
    accept: list[_DependencyId] = Field(default_factory=list, max_length=MapperLimits.MAX_DECISIONS)
    reject: list[_DependencyId] = Field(default_factory=list, max_length=MapperLimits.MAX_DECISIONS)

    @field_validator("accept", "reject", mode="before")
    @classmethod
    def null_is_empty(cls, values: Any) -> Any:
        return [] if values is None else values

    @field_validator("accept", "reject")
    @classmethod
    def drop_blanks_and_repeats(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @model_validator(mode="after")
    def check_the_ids(self) -> "DependencyDecisionRequest":
        """At least one id, none in both lists, at most MapperLimits.MAX_DECISIONS in all."""
        if not self.accept and not self.reject:
            raise ValueError(MapperMessage.NOTHING_TO_DECIDE)
        if both := sorted(set(self.accept) & set(self.reject)):
            raise ValueError(MapperMessage.ACCEPTED_AND_REJECTED.format(ids=", ".join(both)))
        if len(self.accept) + len(self.reject) > MapperLimits.MAX_DECISIONS:
            raise ValueError(MapperMessage.TOO_MANY_DECISIONS.format(limit=MapperLimits.MAX_DECISIONS))
        return self


class DecisionFailure(BaseModel):
    dependency_id: str
    reason: MapperDecisionFailure
    message: str


class DependencyDecisionsResult(MappingView):
    failed: list[DecisionFailure] = []  # the ids not saved, and why; every other id was
