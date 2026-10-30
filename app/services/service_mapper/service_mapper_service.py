"""Service Mapper lifecycle: one mapping per service, runs that only add services, relationship decisions."""

import hashlib
import json
from collections.abc import Callable
from uuid import uuid4

from app.core.clock import utc_now
from app.core.config import Settings
from app.core.constants import (
    AiApi,
    AuditAction,
    AuditTarget,
    MapperConflict,
    MapperDecisionFailure,
    MapperMessage,
    Status,
    TaskName,
)
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Conflict, DuplicateRecord, Forbidden, NotFound
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import new_job
from app.data_access.service_mapper.catalog_repository import ServiceCatalogRepository
from app.data_access.service_mapper.mapping_repository import MappingRepository, request_key
from app.domain.service_mapper.catalog import build_catalog
from app.domain.service_mapper.views import mapping_list_item, mapping_status, mapping_view
from app.domain.shared.audit import audit_target, caller_actor, origin_of_its_jobs
from app.domain.shared.idempotency import duplicate_request
from app.domain.shared.names import name_match_key
from app.models.admin.api_clients import Principal
from app.models.service_mapper.contract import (
    CreateMappingRequest,
    DecisionFailure,
    DependencyDecisionRequest,
    DependencyDecisionsResult,
    EntityServices,
    MappingAccepted,
    MappingList,
    MappingStatus,
    MappingView,
    ServiceRef,
)

_GENERATING = (Status.QUEUED, Status.RUNNING)
_TRIES = 3  # reads of a mapping another call changed at the same moment


class ServiceMapperService:
    def __init__(
        self,
        mappings: MappingRepository,
        settings: Settings,
        send_job: Callable[[TaskName, str, int], bool],
        catalog: ServiceCatalogRepository,
        audit: AuditRepository,
        publish: Callable[[str], None],
    ) -> None:
        self._mappings = mappings
        self._settings = settings
        self._send_job = send_job
        self._catalog = catalog
        self._audit = audit
        self._publish = publish

    @origin_of_its_jobs(AiApi.CREATE_MAPPING)
    def create_service_mapping(
        self,
        principal: Principal,
        body: CreateMappingRequest,
        idempotency_key: str,
        *,
        derived: bool = False,
    ) -> tuple[MappingAccepted, bool]:
        """Generate: the service's mapping, made by its first call; a later call runs it again with these
        details. True when this call started a run."""
        request = body.model_dump()
        input_hash = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        key_hash, service_key = _key_hash(idempotency_key), _service_key(body)
        for _attempt in range(_TRIES):
            if keyed := self._keyed(principal, key_hash):
                return self._replay(keyed, key_hash, derived, lambda claim: claim["input_hash"] == input_hash)
            record = self._mappings.get(
                tenant_id=principal.tenant_id, entity_id=principal.entity_id, service_key=service_key
            )
            if record is None:
                mapping_id = uuid4().hex
                first = _new_record(
                    mapping_id, principal, request, input_hash, service_key, key_hash, self._limits()
                )
                try:
                    self._mappings.create(first)
                except DuplicateRecord:
                    continue  # another call made this service's mapping at the same moment: read it
                self._send_job(TaskName.MAP_SERVICES, mapping_id, 1)
                self._record_change(AuditAction.MAPPING_STARTED, principal, mapping_id, {"generation": 1})
                return MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=1), True
            if record["status"] in _GENERATING:
                if record["input_hash"] != input_hash:
                    raise _still_generating(record)
                return _accepted(record), False  # the same Generate again while it runs: no second job
            if started := self._run_again(principal, record, request, input_hash, key_hash):
                return started
        raise Conflict(MapperMessage.GENERATION_IN_PROGRESS, reason=MapperConflict.GENERATION_IN_PROGRESS)

    @origin_of_its_jobs(AiApi.REGENERATE)
    def regenerate_service_mapping(
        self,
        principal: Principal,
        mapping_id: str,
        idempotency_key: str,
        *,
        derived: bool = False,
    ) -> tuple[MappingAccepted, bool]:
        """Regenerate: the mapping's next run with the details it holds. True when this call started it."""
        key_hash = _key_hash(idempotency_key)
        for _attempt in range(_TRIES):
            if keyed := self._keyed(principal, key_hash):
                return self._replay(keyed, key_hash, derived, lambda _claim: keyed["_id"] == mapping_id)
            record = self._owned(principal, mapping_id)
            if record["status"] in _GENERATING:
                raise _still_generating(record)
            if started := self._run_again(
                principal, record, record["request"], record["input_hash"], key_hash
            ):
                return started
        raise Conflict(MapperMessage.GENERATION_IN_PROGRESS, reason=MapperConflict.GENERATION_IN_PROGRESS)

    def get_service_mapping(self, principal: Principal, mapping_id: str) -> MappingView:
        return mapping_view(self._owned(principal, mapping_id), self._max_generations())

    def get_service_mapping_status(self, principal: Principal, mapping_id: str) -> MappingStatus:
        return mapping_status(self._owned(principal, mapping_id), self._max_generations())

    def get_service_mapping_live_status(
        self,
        principal: Principal,
        mapping_id: str,
    ) -> dict | None:
        try:
            return self.get_service_mapping_status(principal, mapping_id).model_dump(mode="json")
        except MONGO_UNAVAILABLE_ERRORS:
            return None

    def list_entity_services(self, principal: Principal, entity_id: int) -> EntityServices:
        if entity_id != principal.entity_id:
            raise Forbidden(MapperMessage.NOT_YOUR_ENTITY)
        catalog = build_catalog(self._catalog.load())
        services = []
        for service in catalog.services:
            if any(link.entity_id == entity_id for link in service.entities):
                group = service.primary_sector
                services.append(
                    ServiceRef(
                        service_id=service.service_id,
                        name=service.service_name,
                        sector=group.sector_name if group else None,
                        sub_sector=group.subsector_name if group else None,
                    )
                )
        return EntityServices(entity_id=entity_id, services=services)

    def list_service_mappings(
        self,
        principal: Principal,
        entity_id: int | None,
        offset: int,
        limit: int,
    ) -> MappingList:
        if entity_id is not None and entity_id != principal.entity_id:
            raise Forbidden(MapperMessage.NOT_YOUR_ENTITY)
        records = self._mappings.list(
            sort="-created_at",
            skip=offset,
            limit=limit,
            tenant_id=principal.tenant_id,
            entity_id=principal.entity_id,
        )
        max_generations = self._max_generations()
        return MappingList(
            items=[mapping_list_item(record, max_generations) for record in records],
            total=self._mappings.count(tenant_id=principal.tenant_id, entity_id=principal.entity_id),
        )

    def decide_dependencies(
        self,
        principal: Principal,
        mapping_id: str,
        body: DependencyDecisionRequest,
    ) -> DependencyDecisionsResult:
        """Saves every valid accept and reject together, a changed decision too; `failed` names each id not
        found. A run going on meanwhile only adds services, so it never undoes one."""
        desired = dict.fromkeys(body.accept, True) | dict.fromkeys(body.reject, False)
        record = self._owned(principal, mapping_id)
        dependencies = (record.get("result") or {}).get("dependencies")
        if not dependencies:
            raise Conflict(MapperMessage.MAPPING_NOT_READY)
        changes, failed = _sort_decisions(dependencies, desired)
        if changes:
            self._mappings.decide_dependencies(mapping_id, changes, principal.user_id, utc_now())
            saved = {dependency_id: accepted for dependency_id, _direction, accepted in changes}
            self._record_change(
                AuditAction.DEPENDENCY_REVIEWED,
                principal,
                mapping_id,
                {
                    "accepted": [key for key, accepted in saved.items() if accepted],
                    "rejected": [key for key, accepted in saved.items() if not accepted],
                },
            )
            record = self._owned(principal, mapping_id)
        return DependencyDecisionsResult(
            **mapping_view(record, self._max_generations()).model_dump(), failed=failed
        )

    def _run_again(
        self, principal: Principal, record: dict, request: dict, input_hash: str, key_hash: str
    ) -> tuple[MappingAccepted, bool] | None:
        """Start the mapping's next run with `request`: 409 at the run limit; the mapping as it is (no run)
        when it would only repeat the last one; None when another call started one first (read it again)."""
        limit = self._max_generations()
        if limit and record.get("generations_done", 0) >= limit:
            raise Conflict(
                MapperMessage.GENERATION_LIMIT_REACHED.format(limit=limit),
                reason=MapperConflict.GENERATION_LIMIT_REACHED,
                details={"mapping_id": record["_id"], "max_generations": limit},
            )
        if self._would_repeat(record, input_hash):
            return _accepted(record), False
        seen = record["job"]["epoch"]
        if not self._mappings.start_next_run(
            record["_id"], seen, request, input_hash, self._limits(), key_hash, utc_now()
        ):
            return None
        self._send_job(TaskName.MAP_SERVICES, record["_id"], seen + 1)
        self._record_change(
            AuditAction.MAPPING_REGENERATED, principal, record["_id"], {"generation": seen + 1}
        )
        return MappingAccepted(mapping_id=record["_id"], status=Status.QUEUED, generation=seen + 1), True

    def _would_repeat(self, record: dict, input_hash: str) -> bool:
        """Whether a run now would send the AI the very prompt of the last run, which found nothing new: the
        same details, counts and catalog (the AI runs at temperature 0, so it would answer the same)."""
        return (
            record["status"] == Status.DONE
            and record.get("last_run_found") == 0
            and record["input_hash"] == input_hash
            and record.get("limits") == self._limits()
            and (record.get("result") or {}).get("catalog_version")
            == build_catalog(self._catalog.load()).version
        )

    def _keyed(self, principal: Principal, key_hash: str) -> dict | None:
        """The caller's mapping a request with this Idempotency-Key already ran."""
        return self._mappings.get(
            tenant_id=principal.tenant_id, entity_id=principal.entity_id, **{"request_keys.key": key_hash}
        )

    @staticmethod
    def _replay(
        record: dict, key_hash: str, derived: bool, same_request: Callable[[dict], bool]
    ) -> tuple[MappingAccepted, bool]:
        """The run a key started, for its repeat: 409 when the key was sent with another request, and
        duplicate_request when the server derived it."""
        claim = next(claim for claim in record["request_keys"] if claim["key"] == key_hash)
        if not same_request(claim):
            raise Conflict(MapperMessage.IDEMPOTENCY_KEY_CONFLICT)
        if derived:
            raise duplicate_request(claim["at"], mapping_id=record["_id"], generation=claim["generation"])
        accepted = MappingAccepted(
            mapping_id=record["_id"], status=record["status"], generation=claim["generation"]
        )
        return accepted, False

    def _owned(self, principal: Principal, mapping_id: str) -> dict:
        record = self._mappings.get(_id=mapping_id)
        if record is None or record["tenant_id"] != principal.tenant_id:
            raise NotFound(MapperMessage.MAPPING_NOT_FOUND)
        if record["entity_id"] != principal.entity_id:
            raise Forbidden(MapperMessage.NOT_YOUR_ENTITY)
        return record

    def _record_change(
        self,
        action: AuditAction,
        principal: Principal,
        mapping_id: str,
        details: dict,
    ) -> None:
        self._publish(mapping_id)
        self._audit.create_audit_record(
            action,
            caller_actor(principal),
            audit_target(AuditTarget.MAPPING, mapping_id),
            details=details,
        )

    def _limits(self) -> dict[str, int]:
        return {
            "max_upstream": self._settings.service_mapper_upstream_total_count,
            "max_downstream": self._settings.service_mapper_downstream_total_count,
        }

    def _max_generations(self) -> int:
        return self._settings.service_mapper_max_generations


def _new_record(
    mapping_id: str,
    principal: Principal,
    request: dict,
    input_hash: str,
    service_key: str,
    key_hash: str,
    limits: dict,
) -> dict:
    """A new mapping: run 1 queued, no services yet."""
    now = utc_now()
    return {
        "_id": mapping_id,
        "tenant_id": principal.tenant_id,
        "entity_id": principal.entity_id,
        "created_by": principal.user_id,
        "client_id": principal.client_id,
        "request": request,
        "input_hash": input_hash,
        "service_key": service_key,
        "request_keys": [request_key(key_hash, 1, input_hash, now)],
        "generations_done": 0,
        "result": {"selected_service": None, "dependencies": []},
        "status": Status.QUEUED,
        "generation": 1,  # the latest run; MappingRepository's rule requires it
        "limits": limits,
        "job": new_job(TaskName.MAP_SERVICES, 1, now, requested_at=now),
        "created_at": now,
        "updated_at": now,
    }


def _service_key(body: CreateMappingRequest) -> str:
    """Which service a request maps: its name, sector and subsector, case, accents and spacing forgiven."""
    names = (body.service_name, body.sector, body.subsector)
    return hashlib.sha256("\n".join(name_match_key(name) for name in names).encode()).hexdigest()


def _key_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _accepted(record: dict) -> MappingAccepted:
    return MappingAccepted(
        mapping_id=record["_id"], status=record["status"], generation=record["job"]["epoch"]
    )


def _still_generating(record: dict) -> Conflict:
    return Conflict(
        MapperMessage.GENERATION_IN_PROGRESS,
        reason=MapperConflict.GENERATION_IN_PROGRESS,
        details={"mapping_id": record["_id"], "generation": record["job"]["epoch"]},
    )


def _sort_decisions(
    dependencies: list[dict], desired: dict[str, bool]
) -> tuple[list[tuple[str, str, bool]], list[DecisionFailure]]:
    """(the changes to save as (dependency_id, direction, accepted), the ids not found). Each id decides its
    dependency in every direction it has; a direction already decided that way is no change."""
    by_id = {item["dependency_id"]: item for item in dependencies}
    changes: list[tuple[str, str, bool]] = []
    failed: list[DecisionFailure] = []
    for dependency_id, accepted in desired.items():
        dependency = by_id.get(dependency_id)
        if dependency is None:
            failed.append(
                DecisionFailure(
                    dependency_id=dependency_id,
                    reason=MapperDecisionFailure.DEPENDENCY_NOT_FOUND,
                    message=MapperMessage.DEPENDENCY_NOT_FOUND,
                )
            )
            continue
        changes += [
            (dependency_id, direction, accepted)
            for direction, relation in dependency["relations"].items()
            if relation["isAccepted"] != accepted
        ]
    return changes, failed
