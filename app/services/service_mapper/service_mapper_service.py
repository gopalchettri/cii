"""Service Mapper lifecycle: scoped creation, regeneration, history and relationship decisions."""

import hashlib
import json
from collections.abc import Callable
from uuid import uuid4

from app.core.clock import utc_now
from app.core.config import Settings
from app.core.constants import (
    AuditAction,
    AuditTarget,
    ErrorCode,
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
from app.data_access.service_mapper.mapping_repository import MappingHistoryRepository, MappingRepository
from app.domain.service_mapper.catalog import build_catalog
from app.domain.service_mapper.views import mapping_list_item, mapping_status, mapping_view
from app.domain.shared.audit import audit_target, caller_actor
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


class ServiceMapperService:
    def __init__(
        self,
        mappings: MappingRepository,
        history: MappingHistoryRepository,
        settings: Settings,
        send_job: Callable[[TaskName, str, int], None],
        catalog: ServiceCatalogRepository,
        audit: AuditRepository,
        publish: Callable[[str], None],
    ) -> None:
        self._mappings = mappings
        self._history = history
        self._settings = settings
        self._send_job = send_job
        self._catalog = catalog
        self._audit = audit
        self._publish = publish

    def create_service_mapping(
        self,
        principal: Principal,
        body: CreateMappingRequest,
        idempotency_key: str | None,
    ) -> tuple[MappingAccepted, bool]:
        request = body.model_dump()
        fingerprint = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
        key_hash = _key_hash(idempotency_key)
        if key_hash and (earlier := self._created_with_key(principal, key_hash)):
            return self._replay_create(principal, earlier, fingerprint)
        mapping_id = uuid4().hex
        record = _new_record(mapping_id, principal, request, fingerprint, key_hash, self._limits())
        try:
            self._mappings.create(record)
        except DuplicateRecord:
            if not key_hash or not (earlier := self._created_with_key(principal, key_hash)):
                raise
            return self._replay_create(principal, earlier, fingerprint)
        self._send_job(TaskName.MAP_SERVICES, mapping_id, 1)
        self._record_change(AuditAction.MAPPING_STARTED, principal, mapping_id, {"generation": 1})
        return MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=1), True

    def get_service_mapping(self, principal: Principal, mapping_id: str) -> MappingView:
        record = self._owned(principal, mapping_id)
        self._archive_pending(record)
        return mapping_view(record)

    def get_service_mapping_status(self, principal: Principal, mapping_id: str) -> MappingStatus:
        return mapping_status(self._owned(principal, mapping_id))

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
        return MappingList(
            items=[mapping_list_item(record) for record in records],
            total=self._mappings.count(tenant_id=principal.tenant_id, entity_id=principal.entity_id),
        )

    def regenerate_service_mapping(
        self,
        principal: Principal,
        mapping_id: str,
        idempotency_key: str | None,
    ) -> tuple[MappingAccepted, bool]:
        return self._next_generation(principal, mapping_id, _key_hash(idempotency_key), None)

    def _next_generation(
        self, principal: Principal, mapping_id: str, key_hash: str | None, unlisted_generation: int | None
    ) -> tuple[MappingAccepted, bool]:
        """The next generation, or a replay of the one `key_hash` started (`unlisted_generation` when not in
        regen_keys); a replay of the latest generation that failed for an outage is a new try instead."""
        for _attempt in range(3):
            record = self._owned(principal, mapping_id)
            key_generation = (
                record.get("regen_keys", {}).get(key_hash, unlisted_generation) if key_hash else None
            )
            if key_generation is not None and not _failed_for_outage(record, key_generation):
                return MappingAccepted(
                    mapping_id=mapping_id,
                    status=Status.QUEUED,
                    generation=key_generation,
                ), False
            if record["status"] in (Status.QUEUED, Status.RUNNING):
                raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)
            self._archive_pending(record)
            now, generation = utc_now(), record["generation"] + 1
            if self._mappings.start_generation(
                mapping_id,
                record["generation"],
                record["decision_seq"],
                new_job(TaskName.MAP_SERVICES, generation, now),
                key_hash,
                _frozen(record),
                self._limits(),
                now,
            ):
                self._archive_pending(self._owned(principal, mapping_id))
                self._send_job(TaskName.MAP_SERVICES, mapping_id, generation)
                self._record_change(
                    AuditAction.MAPPING_REGENERATED, principal, mapping_id, {"generation": generation}
                )
                started = MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=generation)
                return started, True
        raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)

    def decide_dependencies(
        self,
        principal: Principal,
        mapping_id: str,
        body: DependencyDecisionRequest,
    ) -> DependencyDecisionsResult:
        """Saves every valid accept and reject together; `failed` names each id not saved, and why."""
        desired = dict.fromkeys(body.accept, True) | dict.fromkeys(body.reject, False)
        for _attempt in range(3):
            record = self._owned(principal, mapping_id)
            self._check_decidable(record)
            changes, failed = _sort_decisions(record, desired)
            if not changes:
                return _decisions_result(mapping_view(record), failed)
            if self._mappings.decide_dependencies(
                mapping_id,
                record["generation"],
                record["decision_seq"],
                changes,
                principal.user_id,
                utc_now(),
            ):
                saved = {dependency_id: accepted for dependency_id, _direction, accepted in changes}
                self._record_change(
                    AuditAction.DEPENDENCY_REVIEWED,
                    principal,
                    mapping_id,
                    {
                        "generation": record["generation"],
                        "accepted": [key for key, accepted in saved.items() if accepted],
                        "rejected": [key for key, accepted in saved.items() if not accepted],
                    },
                )
                return _decisions_result(self.get_service_mapping(principal, mapping_id), failed)
        raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)

    def _owned(self, principal: Principal, mapping_id: str) -> dict:
        record = self._mappings.get(_id=mapping_id)
        if record is None or record["tenant_id"] != principal.tenant_id:
            raise NotFound(MapperMessage.MAPPING_NOT_FOUND)
        if record["entity_id"] != principal.entity_id:
            raise Forbidden(MapperMessage.NOT_YOUR_ENTITY)
        return record

    def _created_with_key(self, principal: Principal, key_hash: str) -> dict | None:
        return self._mappings.get(
            tenant_id=principal.tenant_id, entity_id=principal.entity_id, create_key=key_hash
        )

    def _replay_create(
        self, principal: Principal, record: dict, fingerprint: str
    ) -> tuple[MappingAccepted, bool]:
        """The mapping this key created, or a new try of it when the key's generation failed for an outage."""
        if record["input_hash"] != fingerprint:
            raise Conflict(MapperMessage.IDEMPOTENCY_KEY_CONFLICT)
        return self._next_generation(principal, record["_id"], record["create_key"], 1)

    def _archive_pending(self, record: dict) -> None:
        if frozen := record.get("pending_archive"):
            self._history.archive(frozen)
            self._mappings.clear_pending_archive(record["_id"], frozen["generation"])

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

    @staticmethod
    def _check_decidable(record: dict) -> None:
        if record["status"] != Status.DONE or record.get("result") is None:
            raise Conflict(MapperMessage.MAPPING_NOT_READY)


def _new_record(
    mapping_id: str, principal: Principal, request: dict, fingerprint: str, key_hash: str | None, limits: dict
) -> dict:
    """A new mapping's first record: generation 1 queued, nothing decided."""
    now = utc_now()
    return {
        "_id": mapping_id,
        "tenant_id": principal.tenant_id,
        "entity_id": principal.entity_id,
        "created_by": principal.user_id,
        "client_id": principal.client_id,
        "request": request,
        "input_hash": fingerprint,
        "create_key": key_hash,
        "regen_keys": {},
        "decision_seq": 0,
        "generation": 1,
        "result": None,
        "status": Status.QUEUED,
        "active": True,
        "limits": limits,
        "job": new_job(TaskName.MAP_SERVICES, 1, now),
        "created_at": now,
        "updated_at": now,
    }


def _key_hash(value: str | None) -> str | None:
    return hashlib.sha256(value.encode()).hexdigest() if value else None


def _failed_for_outage(record: dict, generation: int) -> bool:
    """Whether `generation` is the latest and failed for an AI or store outage: its key starts a new try."""
    error = record["job"].get("error") or {}
    return (
        record["generation"] == generation
        and record["status"] == Status.FAILED
        and error.get("code") == ErrorCode.UNAVAILABLE
    )


def _sort_decisions(
    record: dict, desired: dict[str, bool]
) -> tuple[list[tuple[str, str, bool]], list[DecisionFailure]]:
    """(the changes to save as (dependency_id, direction, accepted), the ids refused). Each id decides its
    dependency in every direction it has; one already decided the same way is neither."""
    by_id = {item["dependency_id"]: item for item in record["result"]["dependencies"]}
    changes: list[tuple[str, str, bool]] = []
    failed: list[DecisionFailure] = []
    for dependency_id, accepted in desired.items():
        dependency = by_id.get(dependency_id)
        if dependency is None:
            failed.append(_failure(dependency_id, MapperDecisionFailure.DEPENDENCY_NOT_FOUND))
            continue
        relations = dependency["relations"]
        if any(relation["isAccepted"] not in (None, accepted) for relation in relations.values()):
            failed.append(_failure(dependency_id, MapperDecisionFailure.DECISION_FINAL))
            continue
        changes += [
            (dependency_id, direction, accepted)
            for direction, relation in relations.items()
            if relation["isAccepted"] is None
        ]
    return changes, failed


_FAILURE_MESSAGES = {
    MapperDecisionFailure.DEPENDENCY_NOT_FOUND: MapperMessage.DEPENDENCY_NOT_FOUND,
    MapperDecisionFailure.DECISION_FINAL: MapperMessage.DECISION_FINAL,
}


def _failure(dependency_id: str, reason: MapperDecisionFailure) -> DecisionFailure:
    return DecisionFailure(dependency_id=dependency_id, reason=reason, message=_FAILURE_MESSAGES[reason])


def _decisions_result(view: MappingView, failed: list[DecisionFailure]) -> DependencyDecisionsResult:
    return DependencyDecisionsResult(**view.model_dump(), failed=failed)


def _frozen(record: dict) -> dict:
    return {
        "_id": record["_id"],
        "generation": record["generation"],
        "tenant_id": record["tenant_id"],
        "entity_id": record["entity_id"],
        "status": record["status"],
        "result": record.get("result"),
        "error": record.get("job", {}).get("error"),
    }
