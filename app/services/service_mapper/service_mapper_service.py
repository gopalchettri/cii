"""Service Mapper lifecycle: scoped creation, regeneration, history and authoritative reviews."""

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from app.core.config import Settings
from app.core.constants import (
    AuditAction,
    AuditTarget,
    MapperAction,
    MapperConflict,
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
from app.domain.service_mapper.views import mapping_list_item, mapping_view, pending_relationships
from app.domain.shared.audit import audit_target, caller_actor
from app.models.admin.api_clients import Principal
from app.models.jobs.views import retry_notice_of
from app.models.service_mapper.contract import (
    CreateMappingRequest,
    DependencyDecisionRequest,
    EntityServices,
    MappingAccepted,
    MappingDecisionRequest,
    MappingList,
    MappingView,
    ServiceRef,
    StatusEvent,
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
            return self._replay_create(earlier, fingerprint), False
        mapping_id = uuid4().hex
        record = _new_record(mapping_id, principal, request, fingerprint, key_hash, self._limits())
        try:
            self._mappings.create(record)
        except DuplicateRecord:
            if not key_hash or not (earlier := self._created_with_key(principal, key_hash)):
                raise
            return self._replay_create(earlier, fingerprint), False
        self._send_job(TaskName.MAP_SERVICES, mapping_id, 1)
        self._record_change(AuditAction.MAPPING_STARTED, principal, mapping_id, {"generation": 1})
        return MappingAccepted(mapping_id=mapping_id, status=Status.QUEUED, generation=1), True

    def get_service_mapping(self, principal: Principal, mapping_id: str) -> MappingView:
        record = self._owned(principal, mapping_id)
        self._archive_pending(record)
        return mapping_view(record)

    def get_service_mapping_status(self, principal: Principal, mapping_id: str) -> StatusEvent:
        record = self._owned(principal, mapping_id)
        job, status = record.get("job") or {}, record["status"]
        return StatusEvent(
            mapping_id=mapping_id,
            status=status,
            generation=record["generation"],
            retrying=retry_notice_of(status, job.get("retry")),
            error=job.get("error") if status == Status.FAILED else None,
        )

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
        key_hash = _key_hash(idempotency_key)
        for _attempt in range(3):
            record = self._owned(principal, mapping_id)
            if key_hash and key_hash in record.get("regen_keys", {}):
                return MappingAccepted(
                    mapping_id=mapping_id,
                    status=Status.QUEUED,
                    generation=record["regen_keys"][key_hash],
                ), False
            if record["status"] in (Status.QUEUED, Status.RUNNING):
                raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)
            self._archive_pending(record)
            now, generation = datetime.now(UTC), record["generation"] + 1
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

    def decide_mapping(
        self,
        principal: Principal,
        mapping_id: str,
        body: MappingDecisionRequest,
    ) -> MappingView:
        desired = body.action == MapperAction.ACCEPT
        for _attempt in range(3):
            record = self._owned(principal, mapping_id)
            self._check_decidable(record)
            if record["review"] != "pending":
                if (record["review"] == "accepted") == desired:
                    return mapping_view(record)
                raise Conflict(MapperMessage.DECISION_FINAL, reason=MapperConflict.DECISION_FINAL)
            if desired and (pending := pending_relationships(record["result"])):
                raise Conflict(
                    MapperMessage.RELATIONSHIPS_PENDING,
                    reason=MapperConflict.RELATIONSHIPS_PENDING,
                    details={"pending": pending},
                )
            if self._mappings.decide_mapping(
                mapping_id,
                record["generation"],
                record["decision_seq"],
                desired,
                principal.user_id,
                datetime.now(UTC),
            ):
                self._record_change(
                    AuditAction.MAPPING_REVIEWED,
                    principal,
                    mapping_id,
                    {"generation": record["generation"], "accepted": desired}
                    | _decision_counts(record["result"]),
                )
                return self.get_service_mapping(principal, mapping_id)
        raise Conflict(MapperMessage.ROUND_RUNNING, reason=MapperConflict.GENERATION_IN_PROGRESS)

    def decide_dependency(
        self,
        principal: Principal,
        mapping_id: str,
        dependency_id: str,
        body: DependencyDecisionRequest,
    ) -> MappingView:
        desired = body.action == MapperAction.ACCEPT
        for _attempt in range(3):
            record = self._owned(principal, mapping_id)
            self._check_decidable(record)
            relation = _relation(record, dependency_id, body.direction.value)
            if relation["isAccepted"] == desired:
                return mapping_view(record)
            _refuse_change(record, relation)
            if self._mappings.decide_dependency(
                mapping_id,
                record["generation"],
                record["decision_seq"],
                dependency_id,
                body.direction.value,
                desired,
                principal.user_id,
                datetime.now(UTC),
            ):
                self._record_change(
                    AuditAction.DEPENDENCY_REVIEWED,
                    principal,
                    mapping_id,
                    {
                        "generation": record["generation"],
                        "dependency_id": dependency_id,
                        "direction": body.direction.value,
                        "accepted": desired,
                    },
                )
                return self.get_service_mapping(principal, mapping_id)
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

    @staticmethod
    def _replay_create(record: dict, fingerprint: str) -> MappingAccepted:
        if record["input_hash"] != fingerprint:
            raise Conflict(MapperMessage.IDEMPOTENCY_KEY_CONFLICT)
        return MappingAccepted(mapping_id=record["_id"], status=Status.QUEUED, generation=1)

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
    """A new mapping's first record: generation 1 queued, nothing reviewed."""
    now = datetime.now(UTC)
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
        "review": "pending",
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


def _relation(record: dict, dependency_id: str, direction: str) -> dict:
    """One relationship of the current generation: 404 for an unknown dependency, 409 for no such one."""
    dependency = next(
        (item for item in record["result"]["dependencies"] if item["dependency_id"] == dependency_id), None
    )
    if dependency is None:
        raise NotFound(MapperMessage.DEPENDENCY_NOT_FOUND)
    relation = dependency["relations"].get(direction)
    if relation is None:
        raise Conflict(MapperMessage.DIRECTION_NOT_PRESENT)
    return relation


def _refuse_change(record: dict, relation: dict) -> None:
    """409 once the mapping is decided (its relationships freeze) or the relationship has another decision."""
    if record["review"] != "pending":
        raise Conflict(MapperMessage.MAPPING_DECIDED, reason=MapperConflict.DECISION_FINAL)
    if relation["isAccepted"] is not None:
        raise Conflict(MapperMessage.DECISION_FINAL, reason=MapperConflict.DECISION_FINAL)


def _decision_counts(result: dict) -> dict[str, int]:
    """How many relationships of the generation a reviewer accepted and rejected (for the audit)."""
    flags = [
        relation["isAccepted"] for item in result["dependencies"] for relation in item["relations"].values()
    ]
    return {"relationships_accepted": flags.count(True), "relationships_rejected": flags.count(False)}


def _frozen(record: dict) -> dict:
    return {
        "_id": record["_id"],
        "generation": record["generation"],
        "tenant_id": record["tenant_id"],
        "entity_id": record["entity_id"],
        "status": record["status"],
        "review": record["review"],
        "result": record.get("result"),
        "error": record.get("job", {}).get("error"),
    }
