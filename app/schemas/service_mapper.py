"""Public Service Mapper request and response contract."""

from datetime import datetime
from typing import Annotated, Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import AbandonReason, AiOutage, MapperDecisionFailure, MappingOverall, Review, Status
from app.schemas.jobs import RetryNotice

BLANK = "A required value cannot be blank."
_MAX_DECISIONS = 200  # ids per relationship decision: both directions at their largest count (100)


class CreateMappingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    service_name: str = Field(min_length=1, max_length=255)
    service_description: str = Field(min_length=1, max_length=4_000)
    sector: str = Field(min_length=1, max_length=255, validation_alias=AliasChoices("sector", "sector_name"))
    subsector: str = Field(min_length=1, max_length=255, validation_alias=AliasChoices("subsector", "sub_sector_name"))
    entity_names: list[str] = Field(min_length=1, max_length=20)

    @field_validator("service_name", "service_description", "sector", "subsector")
    def strip_required_text(cls, value: str) -> str:
        stripped = " ".join(value.split())
        if not stripped:
            raise ValueError(BLANK)
        return stripped

    @field_validator("entity_names")
    def check_entities(cls, values: list[str]) -> list[str]:
        names = [" ".join(name.split()) for name in values]
        if any(not name or len(name) > 255 for name in names):
            raise ValueError("Each entity name must contain 1 to 255 characters.")
        if len({name.casefold() for name in names}) != len(names):
            raise ValueError("Entity names must be unique.")
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
    reason: AiOutage | AbandonReason | None = None  # the AI outage or the abandon reason that failed it


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
    generation: int
    generations_done: int
    max_generations: int
    upstream_services: list[DependencyService]
    downstream_services: list[DependencyService]
    summary: MappingSummary
    error: MappingError | None = None
    retrying: RetryNotice | None = None
    created_at: datetime
    updated_at: datetime


class MappingListItem(BaseModel):
    mapping_id: str
    status: Status
    generation: int
    generations_done: int
    max_generations: int
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
    accept: list[_DependencyId] = Field(default_factory=list, max_length=_MAX_DECISIONS)
    reject: list[_DependencyId] = Field(default_factory=list, max_length=_MAX_DECISIONS)

    @field_validator("accept", "reject", mode="before")
    def null_is_empty(cls, values: Any) -> Any:
        return [] if values is None else values

    @field_validator("accept", "reject")
    def drop_blanks_and_repeats(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))

    @model_validator(mode="after")
    def check_the_ids(self) -> "DependencyDecisionRequest":
        if not self.accept and not self.reject:
            raise ValueError("Name at least one dependency_id in accept or reject.")
        if both := sorted(set(self.accept) & set(self.reject)):
            raise ValueError(f"A dependency_id cannot be both accepted and rejected: {', '.join(both)}.")
        if len(self.accept) + len(self.reject) > _MAX_DECISIONS:
            raise ValueError(f"At most {_MAX_DECISIONS} dependency ids per request.")
        return self


class DecisionFailure(BaseModel):
    dependency_id: str
    reason: MapperDecisionFailure
    message: str


class DependencyDecisionsResult(MappingView):
    failed: list[DecisionFailure] = []  # the ids not saved, and why; every other id was
