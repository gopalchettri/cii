"""Public Service Mapper request and response contract."""

from datetime import datetime
from enum import StrEnum

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from app.core.constants import MapperAction, MapperDirection, MapperMessage, Status


class MappingReview(StrEnum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


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


class StatusEvent(BaseModel):
    mapping_id: str
    status: Status
    generation: int


class DependencyService(BaseModel):
    dependency_id: str
    service_id: int | None
    service_name: str
    sector: str | None
    subsector: str | None
    dependency_reason: str
    applicability: str | None
    ai_suggested: bool
    isAccepted: bool | None = None
    accepted_datetime: datetime | None = None
    accepted_by: str | None = None


class DirectionalDependency(BaseModel):
    dependency_reason: str
    applicability: str | None
    isAccepted: bool | None = None
    accepted_datetime: datetime | None = None
    accepted_by: str | None = None


class BidirectionalService(BaseModel):
    dependency_id: str
    service_id: int | None
    service_name: str
    sector: str | None
    subsector: str | None
    ai_suggested: bool
    upstream: DirectionalDependency
    downstream: DirectionalDependency


class MappingSummary(BaseModel):
    unique_services: int
    upstream_count: int
    downstream_count: int
    max_upstream: int
    max_downstream: int


class MappingError(BaseModel):
    code: str
    message: str


class MappingView(BaseModel):
    mapping_id: str
    status: Status
    generation: int
    review: MappingReview
    selected_service: SelectedService
    upstream_services: list[DependencyService]
    downstream_services: list[DependencyService]
    bidirectional_services: list[BidirectionalService]
    summary: MappingSummary
    error: MappingError | None = None
    created_at: datetime
    updated_at: datetime


class MappingListItem(BaseModel):
    mapping_id: str
    status: Status
    generation: int
    review: MappingReview
    selected_service: SelectedService
    created_at: datetime
    updated_at: datetime


class MappingList(BaseModel):
    items: list[MappingListItem]
    total: int


class MappingDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: MapperAction


class DependencyDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    direction: MapperDirection
    action: MapperAction
