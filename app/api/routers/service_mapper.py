"""Authenticated Service Mapper creation, polling, listing, regeneration and review APIs."""

from collections.abc import AsyncIterator
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from fastapi import Header as HeaderParam
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.dependencies import Caller
from app.api.status_stream import api_key_still_active, status_stream
from app.container import get_admin_service, get_service_mapper_service
from app.core.constants import ApiTag, Event, Header, Limits, Review
from app.models.service_mapper.contract import (
    CreateMappingRequest,
    DependencyDecisionRequest,
    EntityServices,
    MappingAccepted,
    MappingDecisionRequest,
    MappingList,
    MappingView,
    StatusEvent,
)
from app.realtime.publisher import mapping_channel
from app.services.admin.admin_service import AdminService
from app.services.service_mapper.service_mapper_service import ServiceMapperService

router = APIRouter(tags=[ApiTag.SERVICE_MAPPER])

Mapper = Annotated[ServiceMapperService, Depends(get_service_mapper_service)]
Clients = Annotated[AdminService, Depends(get_admin_service)]
MappingId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
DependencyId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]
IdempotencyKey = Annotated[
    str | None, HeaderParam(alias=Header.IDEMPOTENCY_KEY, max_length=Limits.MAX_IDEMPOTENCY_KEY_CHARS)
]


@router.post("/v1/service-mapper", status_code=202, response_model=MappingAccepted)
def create_mapping(
    body: CreateMappingRequest,
    response: Response,
    principal: Caller,
    mapper: Mapper,
    idempotency_key: IdempotencyKey = None,
) -> MappingAccepted:
    accepted, created = mapper.create_service_mapping(principal, body, idempotency_key)
    if not created:
        response.status_code = 200
    return accepted


@router.get("/v1/service-mapper", response_model=MappingList)
def list_mappings(
    principal: Caller,
    mapper: Mapper,
    entity_id: Annotated[int | None, Query(gt=0, le=Limits.MAX_SQL_INT)] = None,
    offset: Annotated[int, Query(ge=0, le=Limits.MAX_SQL_INT)] = 0,
    limit: Annotated[int, Query(ge=1, le=Limits.PAGE_SIZE_MAX)] = Limits.PAGE_SIZE_DEFAULT,
) -> MappingList:
    return mapper.list_service_mappings(principal, entity_id, offset, limit)


@router.get("/v1/service-mapper/{mapping_id}", response_model=MappingView)
def get_mapping(mapping_id: MappingId, principal: Caller, mapper: Mapper) -> MappingView:
    return mapper.get_service_mapping(principal, mapping_id)


@router.get("/v1/entities/{listed_entity_id}/services", response_model=EntityServices)
def list_entity_services(listed_entity_id: int, principal: Caller, mapper: Mapper) -> EntityServices:
    return mapper.list_entity_services(principal, listed_entity_id)


def mapping_events(mapping_id: MappingId, principal: Caller, mapper: Mapper) -> StatusEvent:
    """Check ownership before opening the stream, so errors remain ordinary HTTP responses."""
    return mapper.get_service_mapping_status(principal, mapping_id)


@router.get("/v1/service-mapper/{mapping_id}/events", response_class=EventSourceResponse)
async def stream_mapping_events(
    mapping_id: MappingId,
    request: Request,
    principal: Caller,
    mapper: Mapper,
    clients: Clients,
    _validated: Annotated[StatusEvent, Depends(mapping_events)],
) -> AsyncIterator[ServerSentEvent]:
    reads = partial(mapper.get_service_mapping_live_status, principal, mapping_id)
    allowed = partial(api_key_still_active, clients, request)
    async for event in status_stream(
        request,
        mapping_channel(mapping_id),
        reads,
        Event.MAPPING_UPDATED,
        allowed,
    ):
        yield event


@router.post("/v1/service-mapper/{mapping_id}/regenerate", status_code=202, response_model=MappingAccepted)
def regenerate_mapping(
    mapping_id: MappingId,
    response: Response,
    principal: Caller,
    mapper: Mapper,
    idempotency_key: IdempotencyKey = None,
) -> MappingAccepted:
    accepted, created = mapper.regenerate_service_mapping(principal, mapping_id, idempotency_key)
    if not created:
        response.status_code = 200
    return accepted


@router.post("/v1/service-mapper/{mapping_id}/decision", response_model=MappingView)
def decide_mapping(
    mapping_id: MappingId,
    body: MappingDecisionRequest,
    principal: Caller,
    mapper: Mapper,
) -> MappingView:
    return mapper.decide_mapping(principal, mapping_id, body)


@router.post(
    "/v1/service-mapper/{mapping_id}/dependencies/{dependency_id}/decision",
    response_model=MappingView,
)
def decide_dependency(
    mapping_id: MappingId,
    dependency_id: DependencyId,
    body: DependencyDecisionRequest,
    principal: Caller,
    mapper: Mapper,
) -> MappingView:
    return mapper.decide_dependency(principal, mapping_id, dependency_id, body)
