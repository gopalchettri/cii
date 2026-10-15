"""The Service Mapper API (a stub: canned answers, real authentication, validation and error shapes): create a
mapping, read it, an entity's services, regenerate, accept or reject a recommendation, and a live status
stream. Each route makes one service call.

Fixed ids give the error responses: mapping 00000000000000000000000000000000 is unknown (404); regenerate on
mapping ...0001 is 409 generation_in_progress; deciding recommendation ...0002 is 409 decision_final and
...0003 is 409 superseded."""

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, Depends, Path
from fastapi import Header as HeaderParam
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.dependencies import Caller
from app.core.constants import ApiTag, Header, Limits, MapperEvent, Realtime, Review
from app.models.service_map import (
    CreateMappingRequest,
    DecisionRequest,
    DecisionResult,
    EntityServices,
    MappingAccepted,
    MappingView,
    StatusEvent,
)
from app.services.service_mapper.stub import ServiceMapperStub, get_service_mapper

router = APIRouter(tags=[ApiTag.SERVICE_MAPPER])

Mapper = Annotated[ServiceMapperStub, Depends(get_service_mapper)]
MappingId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
RecommendationId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
IdempotencyKey = Annotated[
    str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
]


@router.post(
    "/v1/service-mapper", status_code=202, response_model=MappingAccepted, summary="1. Create a mapping"
)
def create_mapping(
    body: CreateMappingRequest, principal: Caller, mapper: Mapper, idempotency_key: IdempotencyKey = None
) -> MappingAccepted:
    """A stub with fixed answers, for integration tests (real keys, checks and error shapes). 202 with
    `mapping_id`."""
    return mapper.create(principal, body, idempotency_key)


@router.get("/v1/service-mapper/{mapping_id}", response_model=MappingView, summary="2. Read a mapping")
def get_mapping(mapping_id: MappingId, principal: Caller, mapper: Mapper) -> MappingView:
    """The mapping and its recommendations."""
    return mapper.get(principal, mapping_id)


@router.get(
    # {listed_entity_id}, not {entity_id}: that name is the X-Entity-Id parameter of the identity check.
    "/v1/entities/{listed_entity_id}/services",
    response_model=EntityServices,
    summary="3. An entity's services",
)
def list_entity_services(listed_entity_id: int, principal: Caller, mapper: Mapper) -> EntityServices:
    """The entity's services; the entity must be the caller's, else 403."""
    return mapper.entity_services(principal, listed_entity_id)


@router.post(
    "/v1/service-mapper/{mapping_id}/regenerate",
    status_code=202,
    response_model=MappingAccepted,
    summary="4. A new round of suggestions",
)
def regenerate_mapping(
    mapping_id: MappingId, principal: Caller, mapper: Mapper, idempotency_key: IdempotencyKey = None
) -> MappingAccepted:
    """202. Mapping `...0001` answers 409 `generation_in_progress`, for testing."""
    return mapper.regenerate(principal, mapping_id, idempotency_key)


@router.patch(
    "/v1/service-mapper/recommendations/{recommendation_id}/decision",
    response_model=DecisionResult,
    summary="5. Accept or reject a suggestion",
)
def decide_recommendation(
    recommendation_id: RecommendationId, body: DecisionRequest, principal: Caller, mapper: Mapper
) -> DecisionResult:
    """Recommendation `...0002` answers 409 `decision_final` and `...0003` 409 `superseded`, for
    testing."""
    return mapper.decide(principal, recommendation_id, body)


def mapping_events(mapping_id: MappingId, principal: Caller, mapper: Mapper) -> list[StatusEvent]:
    """Runs before the stream starts, so an unknown mapping (404) or another caller's is an ordinary problem
    response, not a broken stream."""
    return mapper.events(principal, mapping_id)


@router.get(
    "/v1/service-mapper/{mapping_id}/events",
    response_class=EventSourceResponse,
    summary="6. A mapping's live status",
)
async def stream_mapping_events(
    events: Annotated[list[StatusEvent], Depends(mapping_events)],
) -> AsyncIterator[ServerSentEvent]:
    """Server-Sent Events of the mapping's status."""
    for event in events:
        yield ServerSentEvent(
            event=MapperEvent.STATUS, data=event.model_dump(mode="json"), retry=Realtime.RETRY_MS
        )
