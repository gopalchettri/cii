"""Service Mapper lifecycle: one mapping per service, runs that only add services, relationship decisions."""

import hashlib
import json
from collections.abc import Callable
from uuid import uuid4

from pymongo.database import Database

from app import worker
from app.core import constants as c
from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.exceptions import Conflict, DuplicateRecord, Forbidden, NotFound
from app.core.security import Principal
from app.crud import service_mapper as crud
from app.crud.audit import get_audit_repository
from app.domain.service_mapper.catalog import catalog_snapshot
from app.domain.shared.audit import audit_target, caller_actor, origin_of_its_jobs
from app.domain.shared.idempotency import duplicate_request
from app.domain.shared.names import name_match_key
from app.realtime import publisher
from app.schemas import service_mapper as schemas
from app.schemas.jobs import retry_notice_of

_GENERATING = (c.Status.QUEUED, c.Status.RUNNING)
_TRIES = 3  # reads of a mapping another call changed at the same moment
_NOT_YOURS = "entity_id must be the caller's entity (the X-Entity-Id header)."
_IN_PROGRESS = "This mapping is still being generated: wait for this run to finish."

Started = tuple[schemas.MappingAccepted, bool]  # the run, and whether this call started it


@origin_of_its_jobs(c.AiApi.CREATE_MAPPING)
def create_mapping(
    db: Database, principal: Principal, body: schemas.CreateMappingRequest, key: str, derived: bool
) -> Started:
    """Generate: the first call makes the service's mapping; a later call runs it again with these details."""
    request = body.model_dump()
    input_hash, key_hash = _sha256(json.dumps(request, sort_keys=True)), _sha256(key)
    names = (body.service_name, body.sector, body.subsector)
    service_key = _sha256("\n".join(name_match_key(name) for name in names))  # case, accents, spacing forgiven
    callers = {"tenant_id": principal.tenant_id, "entity_id": principal.entity_id}
    for _attempt in range(_TRIES):
        if keyed := crud.get_mapping(db, **callers, **{"request_keys.key": key_hash}):
            return _replay(keyed, key_hash, derived, lambda claim: claim["input_hash"] == input_hash)
        record = crud.get_mapping(db, **callers, service_key=service_key)
        if record is None:
            record = _new_record(principal, request, input_hash, service_key, key_hash)
            try:
                crud.insert_mapping(db, record)
            except DuplicateRecord:
                continue  # another call made this service's mapping at the same moment: read it
            return _started(principal, record["_id"], 1, c.AuditAction.MAPPING_STARTED)
        if record["status"] in _GENERATING:
            if record["input_hash"] != input_hash:
                raise _still_generating(record)
            claim = crud.request_key(key_hash, record["job"]["epoch"], input_hash, utc_now())
            crud.add_request_key(db, record["_id"], claim)  # so a retry of this key replays it
            return _accepted(record), False  # the same Generate again while it runs: no second job
        if started := _run_again(db, principal, record, request, input_hash, key_hash):
            return started
    raise Conflict(_IN_PROGRESS, reason=c.MapperConflict.GENERATION_IN_PROGRESS)


@origin_of_its_jobs(c.AiApi.REGENERATE)
def regenerate_mapping(db: Database, principal: Principal, mapping_id: str, key: str, derived: bool) -> Started:
    """Regenerate: the mapping's next run with the details it holds."""
    key_hash = _sha256(key)
    for _attempt in range(_TRIES):
        keyed = crud.get_mapping(
            db, tenant_id=principal.tenant_id, entity_id=principal.entity_id, **{"request_keys.key": key_hash}
        )
        if keyed:
            same = keyed["_id"] == mapping_id
            return _replay(keyed, key_hash, derived, lambda _claim: same)  # noqa: B023 (returned at once)
        record = owned_mapping(db, principal, mapping_id)
        if record["status"] in _GENERATING:
            raise _still_generating(record)
        if started := _run_again(db, principal, record, record["request"], record["input_hash"], key_hash):
            return started
    raise Conflict(_IN_PROGRESS, reason=c.MapperConflict.GENERATION_IN_PROGRESS)


def _run_again(
    db: Database, principal: Principal, record: dict, request: dict, input_hash: str, key_hash: str
) -> Started | None:
    limit, limits = get_settings().service_mapper_max_generations, _limits()
    if limit and record.get("generations_done", 0) >= limit:
        raise Conflict(
            f"This mapping has had its {limit} runs (SERVICE_MAPPER_MAX_GENERATIONS).",
            reason=c.MapperConflict.GENERATION_LIMIT_REACHED,
            details={"mapping_id": record["_id"], "max_generations": limit},
        )
    if (  # the last run found nothing new, and the AI (temperature 0) would get the very same prompt
        record["status"] == c.Status.DONE
        and record.get("last_run_found") == 0
        and record["input_hash"] == input_hash
        and record.get("limits") == limits
        and (record.get("result") or {}).get("catalog_version") == catalog_snapshot().version
    ):
        return _accepted(record), False
    if not crud.start_next_run(db, record, request, input_hash, limits, key_hash):
        return None
    return _started(principal, record["_id"], record["job"]["epoch"] + 1, c.AuditAction.MAPPING_REGENERATED)


def _replay(record: dict, key_hash: str, derived: bool, same_request: Callable[[dict], bool]) -> Started:
    claim = next(claim for claim in record["request_keys"] if claim["key"] == key_hash)
    if not same_request(claim):
        raise Conflict("This Idempotency-Key was already used for another mapping input.")
    if derived:
        raise duplicate_request(claim["at"], mapping_id=record["_id"], generation=claim["generation"])
    return schemas.MappingAccepted(
        mapping_id=record["_id"], status=record["status"], generation=claim["generation"]
    ), False


def _started(principal: Principal, mapping_id: str, run: int, action: c.AuditAction) -> Started:
    worker.send_job(c.TaskName.MAP_SERVICES, mapping_id, run)
    _changed(principal, mapping_id, action, {"generation": run})
    return schemas.MappingAccepted(mapping_id=mapping_id, status=c.Status.QUEUED, generation=run), True


def _changed(principal: Principal, mapping_id: str, action: c.AuditAction, details: dict) -> None:
    publisher.publish_mapping_status(mapping_id)
    target = audit_target(c.AuditTarget.MAPPING, mapping_id)
    get_audit_repository().create_audit_record(action, caller_actor(principal), target, details=details)


def _new_record(principal: Principal, request: dict, input_hash: str, service_key: str, key_hash: str) -> dict:
    now = utc_now()
    return {
        "_id": uuid4().hex,
        "tenant_id": principal.tenant_id,
        "entity_id": principal.entity_id,
        "created_by": principal.user_id,
        "client_id": principal.client_id,
        "service_key": service_key,
        "request_keys": [crud.request_key(key_hash, 1, input_hash, now)],
        "generations_done": 0,
        "result": {"selected_service": None, "dependencies": []},
        "created_at": now,
    } | crud.run_fields(1, request, input_hash, _limits(), now)


def _limits() -> dict[str, int]:
    settings = get_settings()
    return {
        "max_upstream": settings.service_mapper_upstream_total_count,
        "max_downstream": settings.service_mapper_downstream_total_count,
    }


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _accepted(record: dict) -> schemas.MappingAccepted:
    return schemas.MappingAccepted(mapping_id=record["_id"], status=record["status"], generation=record["job"]["epoch"])


def _still_generating(record: dict) -> Conflict:
    return Conflict(
        _IN_PROGRESS,
        reason=c.MapperConflict.GENERATION_IN_PROGRESS,
        details={"mapping_id": record["_id"], "generation": record["job"]["epoch"]},
    )


def owned_mapping(db: Database, principal: Principal, mapping_id: str) -> dict:
    """The caller's mapping: 404 when there is none, 403 when it is another entity's."""
    record = crud.get_mapping(db, _id=mapping_id)
    if record is None or record["tenant_id"] != principal.tenant_id:
        raise NotFound("No such mapping.")
    if record["entity_id"] != principal.entity_id:
        raise Forbidden(_NOT_YOURS)
    return record


def list_mappings(
    db: Database, principal: Principal, entity_id: int | None, offset: int, limit: int
) -> schemas.MappingList:
    if entity_id is not None and entity_id != principal.entity_id:
        raise Forbidden(_NOT_YOURS)
    records, total = crud.list_mappings(db, principal.tenant_id, principal.entity_id, offset, limit)
    items = [
        schemas.MappingListItem(
            **_shown(record), selected_service=(record.get("result") or {}).get("selected_service") or record["request"]
        )
        for record in records
    ]
    return schemas.MappingList(items=items, total=total)


def list_entity_services(principal: Principal, entity_id: int) -> schemas.EntityServices:
    if entity_id != principal.entity_id:
        raise Forbidden(_NOT_YOURS)
    services = []
    for service in catalog_snapshot().services:
        if any(link.entity_id == entity_id for link in service.entities):
            sector, sub_sector = service.primary_names
            services.append(
                schemas.ServiceRef(
                    service_id=service.service_id, name=service.service_name, sector=sector, sub_sector=sub_sector
                )
            )
    return schemas.EntityServices(entity_id=entity_id, services=services)


def decide_dependencies(
    db: Database, principal: Principal, mapping_id: str, body: schemas.DependencyDecisionRequest
) -> schemas.DependencyDecisionsResult:
    """Saves every valid accept and reject together; `failed` names each id not found."""
    desired = dict.fromkeys(body.accept, True) | dict.fromkeys(body.reject, False)
    record = owned_mapping(db, principal, mapping_id)
    by_id = {item["dependency_id"]: item for item in (record.get("result") or {}).get("dependencies") or []}
    if not by_id:
        raise Conflict(
            "The mapping has no services to decide yet: wait for its first run, or regenerate it if it failed."
        )
    changes = [  # (dependency_id, direction, accepted): each id decides every direction it has
        (dependency_id, direction, accepted)
        for dependency_id, accepted in desired.items()
        for direction, relation in by_id.get(dependency_id, {"relations": {}})["relations"].items()
        if relation["isAccepted"] != accepted
    ]
    if changes:
        saved_record = crud.save_decisions(db, mapping_id, changes, principal.user_id, utc_now())
        if saved_record is None:  # no path deletes a mapping; kept so a vanished one is a 404, not a 500
            raise NotFound("No such mapping.")
        record = saved_record
        saved = {dependency_id: accepted for dependency_id, _direction, accepted in changes}
        decided = {
            "accepted": [i for i, yes in saved.items() if yes],
            "rejected": [i for i, yes in saved.items() if not yes],
        }
        _changed(principal, mapping_id, c.AuditAction.DEPENDENCY_REVIEWED, decided)
    failed = [
        schemas.DecisionFailure(
            dependency_id=dependency_id,
            reason=c.MapperDecisionFailure.DEPENDENCY_NOT_FOUND,
            message="No such dependency in this mapping.",
        )
        for dependency_id in desired
        if dependency_id not in by_id
    ]
    return schemas.DependencyDecisionsResult(**mapping_view(record).model_dump(), failed=failed)


def mapping_view(record: dict) -> schemas.MappingView:
    dependencies = (record.get("result") or {}).get("dependencies") or []
    shown: dict[str, list[schemas.DependencyService]] = {"upstream": [], "downstream": []}
    for dependency in dependencies:
        for direction, relation in dependency["relations"].items():  # one, or both in an older record
            shown[direction].append(schemas.DependencyService(**dependency, **relation))
    limits = record.get("limits") or {}
    summary = schemas.MappingSummary(
        unique_services=len(dependencies),
        upstream_count=len(shown["upstream"]),
        downstream_count=len(shown["downstream"]),
        max_upstream=limits.get("max_upstream", 0),
        max_downstream=limits.get("max_downstream", 0),
    )
    return schemas.MappingView(
        **_shown(record), upstream_services=shown["upstream"], downstream_services=shown["downstream"], summary=summary
    )


def mapping_status(record: dict) -> schemas.MappingStatus:
    flags = [
        relation["isAccepted"]
        for dependency in (record.get("result") or {}).get("dependencies", [])
        for relation in dependency["relations"].values()
    ]
    seconds = record["job"].get("timings") or {}
    progress = schemas.MappingProgress(
        overall=c.MappingOverall.GENERATING if record["status"] in _GENERATING else c.MappingOverall(record["status"]),
        relationships=schemas.RelationshipCounts(
            total=len(flags), accepted=flags.count(True), rejected=flags.count(False), pending=flags.count(None)
        ),
        timings=schemas.MappingTimings(catalog=seconds.get("catalog_s"), services=seconds.get("services_s")),
    )
    return schemas.MappingStatus(
        **_shown(record), entity_id=record["entity_id"], user_id=record.get("created_by"), progress=progress
    )


def _shown(record: dict) -> dict:
    status, job = record["status"], record["job"]
    return {
        "mapping_id": record["_id"],
        "status": status,
        "generation": job["epoch"],
        "generations_done": record.get("generations_done", 0),
        "max_generations": get_settings().service_mapper_max_generations,
        "retrying": retry_notice_of(status, job.get("retry")),
        "error": job.get("error") if status == c.Status.FAILED else None,
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }
