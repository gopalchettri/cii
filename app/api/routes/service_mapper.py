"""Service Mapper generation, polling, listing, regeneration and relationship decision APIs."""

from collections.abc import AsyncIterator
from functools import partial
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from fastapi.sse import EventSourceResponse, ServerSentEvent

from app.api.deps import Caller, DbDep, IdempotencyKey
from app.api.status_stream import status_stream
from app.core.constants import ApiTag, Event, Header, Limits, Review
from app.crud import admin as admin_crud
from app.domain.service_mapper import mappings
from app.realtime.publisher import mapping_channel
from app.schemas import service_mapper as schemas

router = APIRouter(tags=[ApiTag.SERVICE_MAPPER])
MappingId = Annotated[str, Path(max_length=Review.MAX_ID_CHARS)]


def callers_mapping(mapping_id: MappingId, principal: Caller, db: DbDep) -> dict:
    """The caller's mapping: 404 when there is none, 403 when it is another entity's."""
    return mappings.owned_mapping(db, principal, mapping_id)


CallersMapping = Annotated[dict, Depends(callers_mapping)]


@router.post("/v1/service-mapper", status_code=202, response_model=schemas.MappingAccepted)
def create_mapping(
    body: schemas.CreateMappingRequest,
    response: Response,
    principal: Caller,
    idempotency_key: IdempotencyKey,
    db: DbDep,
) -> schemas.MappingAccepted:
    """Generate. A service (name, sector and subsector) has one mapping per entity: the first call makes it
    and starts run 1 (202); a later call starts its next run with these details (202, same `mapping_id`),
    which only adds services the mapping does not hold yet. While a run goes on, the same body answers 200
    with it and another body 409 `generation_in_progress`; past SERVICE_MAPPER_MAX_GENERATIONS runs, 409
    `generation_limit_reached`. After a run that found nothing new, the same body answers 200 with the mapping
    as it is (no run, none used) until the counts or the catalog change. The same Idempotency-Key answers 200
    with the run it started; without a key, the same body again within a minute is 409 `duplicate_request`."""
    accepted, started = mappings.create_mapping(db, principal, body, *idempotency_key)
    response.status_code = 202 if started else 200
    return accepted


@router.get("/v1/service-mapper", response_model=schemas.MappingList)
def list_mappings(
    principal: Caller,
    db: DbDep,
    entity_id: Annotated[int | None, Query(gt=0, le=Limits.MAX_SQL_INT)] = None,
    offset: Annotated[int, Query(ge=0, le=Limits.MAX_SQL_INT)] = 0,
    limit: Annotated[int, Query(ge=1, le=Limits.PAGE_SIZE_MAX)] = Limits.PAGE_SIZE_DEFAULT,
) -> schemas.MappingList:
    return mappings.list_mappings(db, principal, entity_id, offset, limit)


@router.get("/v1/service-mapper/{mapping_id}", response_model=schemas.MappingView)
def get_mapping(mapping: CallersMapping) -> schemas.MappingView:
    return mappings.mapping_view(mapping)


@router.get("/v1/service-mapper/{mapping_id}/status", response_model=schemas.MappingStatus)
def get_mapping_status(mapping: CallersMapping) -> schemas.MappingStatus:
    """Poll until `progress.overall` is no longer `generating`: `done` (decide the relationships;
    `progress.relationships` counts them), `failed` (`error` says why) or `cancelled`."""
    return mappings.mapping_status(mapping)


@router.get("/v1/entities/{listed_entity_id}/services", response_model=schemas.EntityServices)
def list_entity_services(listed_entity_id: int, principal: Caller) -> schemas.EntityServices:
    return mappings.list_entity_services(principal, listed_entity_id)


@router.get("/v1/service-mapper/{mapping_id}/events", response_class=EventSourceResponse)
async def stream_mapping_events(
    mapping_id: MappingId, request: Request, principal: Caller, db: DbDep, _owned: CallersMapping
) -> AsyncIterator[ServerSentEvent]:
    def read() -> dict:
        return mappings.mapping_status(mappings.owned_mapping(db, principal, mapping_id)).model_dump(mode="json")

    allowed = partial(admin_crud.api_key_still_active, db, request.headers.get(Header.API_KEY, ""))
    async for event in status_stream(request, mapping_channel(mapping_id), read, Event.MAPPING_UPDATED, allowed):
        yield event


@router.post("/v1/service-mapper/{mapping_id}/regenerate", status_code=202, response_model=schemas.MappingAccepted)
def regenerate_mapping(
    mapping_id: MappingId, response: Response, principal: Caller, idempotency_key: IdempotencyKey, db: DbDep
) -> schemas.MappingAccepted:
    """202 starts the mapping's next run with the details it holds: it only adds services the mapping does
    not hold yet; every service and decision stays. 409 `generation_in_progress` while a run goes on, 409
    `generation_limit_reached` past SERVICE_MAPPER_MAX_GENERATIONS runs (a failed run does not count). After
    a run that found nothing new, 200 with the mapping as it is (no run, none used) until its details, the
    counts or the catalog change. The same Idempotency-Key answers 200 with the run it started; without a
    key, a repeat within a minute is 409 `duplicate_request`."""
    accepted, started = mappings.regenerate_mapping(db, principal, mapping_id, *idempotency_key)
    response.status_code = 202 if started else 200
    return accepted


@router.post("/v1/service-mapper/{mapping_id}/dependencies/decision", response_model=schemas.DependencyDecisionsResult)
def decide_dependencies(
    mapping_id: MappingId, body: schemas.DependencyDecisionRequest, principal: Caller, db: DbDep
) -> schemas.DependencyDecisionsResult:
    """Send `{"accept": [dependency_id, ...], "reject": [...]}`; either list may be null or empty. The valid
    ids are saved together, a changed decision too; `failed` lists each id that was not, and why. Allowed
    while a later run goes on; 409 while the mapping has no services yet."""
    return mappings.decide_dependencies(db, principal, mapping_id, body)
