"""Request and response models of the Service Mapper API."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.constants import (
    MapperAction,
    MapperConfidence,
    MapperDirection,
    MapperLimits,
    MapperMessage,
    MapperRecommendationStatus,
    Status,
)
from app.models.scenario.views import SqlId


class CreateMappingRequest(BaseModel):
    """Body of POST /v1/service-mapper: one service of an entity, an existing one (`service_id`) or a new one
    (`service_name`, with its sector and sub-sector when known). An unknown field is refused (422)."""

    model_config = ConfigDict(extra="forbid")

    entity_id: SqlId
    service_id: SqlId | None = None
    service_name: str | None = Field(
        default=None, min_length=1, max_length=MapperLimits.MAX_SERVICE_NAME_CHARS
    )
    sector_id: SqlId | None = None
    sub_sector_id: SqlId | None = None

    @field_validator("service_name")
    @classmethod
    def strip_the_name(cls, name: str | None) -> str | None:
        return name.strip() if name is not None else None

    @model_validator(mode="after")
    def exactly_one_service(self) -> "CreateMappingRequest":
        if (self.service_id is None) == (not self.service_name):
            raise ValueError(MapperMessage.ONE_SERVICE_ONLY)
        return self


class DecisionRequest(BaseModel):
    """Body of PATCH .../decision: accept or reject one recommendation, with an optional comment."""

    model_config = ConfigDict(extra="forbid")

    action: MapperAction
    reviewer_comment: str | None = Field(default=None, max_length=MapperLimits.MAX_COMMENT_CHARS)


class MappingAccepted(BaseModel):
    """What a create or a regenerate answers at once: the job is queued, the result comes later."""

    mapping_id: str
    status: Status
    generation: int


class ServiceRef(BaseModel):
    """A service with its own sector and sub-sector; `service_id` is null for a service the AI named."""

    service_id: int | None
    name: str
    sector: str | None
    sub_sector: str | None


class DecisionInfo(BaseModel):
    by: str
    at: datetime
    comment: str | None


class Recommendation(BaseModel):
    """One suggested service. `ai_generated` is true exactly when `related_service_id` is null."""

    recommendation_id: str
    generation: int
    direction: MapperDirection
    related_service_id: int | None
    name: str
    sector: str | None
    sub_sector: str | None
    cross_sector: bool | None = Field(description="True when its sector differs from the selected service's.")
    ai_generated: bool
    reason: str
    confidence: MapperConfidence
    status: MapperRecommendationStatus
    decision: DecisionInfo | None


class MappingError(BaseModel):
    code: str
    message: str


class MappingView(BaseModel):
    """A mapping: its status and every recommendation of every round."""

    mapping_id: str
    entity_id: int
    status: Status
    generation: int
    error: MappingError | None
    service: ServiceRef
    recommendations: list[Recommendation]


class DecisionResult(BaseModel):
    recommendation_id: str
    status: MapperRecommendationStatus
    decision: DecisionInfo


class EntityServices(BaseModel):
    entity_id: int
    services: list[ServiceRef]


class StatusEvent(BaseModel):
    """Data of a live-status event: ids and status only; the result is read with GET."""

    mapping_id: str
    status: Status
    generation: int
