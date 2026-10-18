"""The admin's view and control of external intelligence: the run-time switch, refreshes on request (admin
job kind intel_refresh), the health report with the evidence settings, and the sources' approval. With the
env master switch off no intelligence store is read."""

import uuid
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.callables import SendAdminJob
from app.core.config import Settings
from app.core.constants import (
    AdminJobKind,
    AdminJobMessage,
    AuditAction,
    AuditTarget,
    IntelDocId,
    IntelRefreshMessage,
    IntelSource,
    LogEvent,
    Status,
    TaskName,
)
from app.core.exceptions import Conflict, Invalid, NotFound
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.data_access.external_intelligence.intel_snapshot_repository import IntelSnapshotRepository
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.domain.external_intelligence.evidence_settings import evidence_settings
from app.domain.shared.audit import admin_actor, audit_target
from app.models.external_intelligence.source_health import (
    FeedFreshness,
    HealthReport,
    source_health_in_registry_order,
    sources_in_registry_order,
)
from app.models.external_intelligence.switch_state import SwitchState
from app.search.external_intelligence.index_keeper import EvidenceIndexKeeper
from app.services.admin.admin_service import queue_admin_job

log = structlog.get_logger(__name__)
_KIND = AdminJobKind.INTEL_REFRESH


class ExternalIntelligenceService:
    """The admin API's external intelligence actions."""

    def __init__(
        self,
        settings: Settings,
        switch: IntelligenceSwitch,
        feeds: IntelFeedRepository,
        records: IntelRecordRepository,
        snapshots: IntelSnapshotRepository,
        vectors: EmbeddingRepository,
        admin_jobs: AdminJobRepository,
        audit: AuditRepository,
        index_keeper: EvidenceIndexKeeper,
        send_admin_job: SendAdminJob,
    ) -> None:
        self._settings, self._switch, self._feeds, self._records = settings, switch, feeds, records
        self._snapshots, self._vectors, self._jobs, self._audit = snapshots, vectors, admin_jobs, audit
        self._keeper, self._send_admin_job = index_keeper, send_admin_job

    def get_intelligence_switch_state(self) -> dict[str, Any]:
        """The switch state; with the env master off it answers from the environment alone."""
        return self._switch.state().as_doc()

    def update_intelligence_switch_state(self, enabled: bool, changed_by: str) -> dict[str, Any]:
        """Set, audit and log the run-time switch (409 while the env master switch is off; a store that cannot
        be written raises, nothing changed or audited); turning it on also queues a refresh, so the first
        data does not wait for the hourly check."""
        if not self._settings.external_intelligence_enabled:  # nothing of the feature is written while off
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        before = self._switch.state()
        after = self._switch.save(enabled, changed_by)
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, IntelDocId.SWITCH)
        self._audit.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED,
            admin_actor(changed_by),
            target,
            before=_flags(before),
            after=_flags(after),
        )
        log.info(LogEvent.EXTERNAL_INTELLIGENCE_SWITCH_CHANGED, enabled=enabled, changed_by=changed_by)
        if enabled and after.effective:
            self._queue_refresh(changed_by)
        return after.as_doc()

    def create_intelligence_refresh(
        self, requested_by: str, source: IntelSource | None = None
    ) -> dict[str, Any]:
        """Queue a refresh and return its id. 409 while the switch is off; 422 for a source not approved; 409
        job_in_progress (details.job_id: the active one) while one is queued or running; 503 when the job
        queue is unreachable (the job is then failed, never left queued)."""
        if not self._switch.is_on():
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        if source is not None and not self._feeds.count(_id=source, approved=True):
            raise Invalid(IntelRefreshMessage.SOURCE_NOT_APPROVED.format(source=source))
        job_id = uuid.uuid4().hex
        job: dict[str, Any] = {
            "_id": job_id,
            "kind": _KIND,
            "status": Status.QUEUED,
            "requested_by": requested_by,
            "source": source,
        }
        queue_admin_job(
            self._jobs,
            self._send_admin_job,
            TaskName.REFRESH_EXTERNAL_INTELLIGENCE,
            job,
            IntelRefreshMessage.IN_PROGRESS,
            IntelRefreshMessage.NOT_SENT,
        )
        target = audit_target(AuditTarget.ADMIN_JOB, job_id)
        after = {"kind": _KIND, "source": source}
        self._audit.create_audit_record(
            AuditAction.ADMIN_JOB_STARTED, admin_actor(requested_by), target, after=after
        )
        return {"job_id": job_id, "status": Status.QUEUED}

    def get_intelligence_refresh(self, job_id: str) -> dict[str, Any]:
        """One refresh job as the API shows it; 404 for any other job."""
        record = self._jobs.get_admin_job(job_id, _KIND)
        if record is None:
            raise NotFound(AdminJobMessage.NOT_FOUND.format(job_id=job_id))
        return {"job_id": record.pop("_id"), **record}

    def get_intelligence_health(self) -> dict[str, Any]:
        """The health report with the evidence settings: an approved source that never succeeded is pending,
        not stale; the snapshot is the fleet's active one, else the one this process serves. Reading starts no
        build. With the master switch off, only the switch state."""
        settings = self._settings
        evidence = evidence_settings(settings.rerank_model, settings.evidence_similarity_threshold)
        if not settings.external_intelligence_enabled:
            state = SwitchState(env_enabled=False).as_doc()  # no store is read while off
            return {
                "switch": state,
                "snapshot_id": None,
                "sources": [],
                "stale": False,
                "pending_sources": [],
                "no_data": False,
                "evidence": evidence,
            }
        sources = tuple(source_health_in_registry_order(self._feeds.list(sources=True)))
        approved = sources_in_registry_order(self._feeds.list(["_id"], sources=True, approved=True))
        freshness = FeedFreshness.of(sources, approved, datetime.now(UTC))
        active = self._snapshots.get("description", _id=IntelDocId.ACTIVE_SNAPSHOT)
        snapshot_id = active.get("snapshot_id") if active else self._keeper.peek_index().snapshot_id
        report = HealthReport(
            self._switch.state(), snapshot_id, sources, freshness.stale, freshness.pending, freshness.no_data
        )
        return report.as_doc() | {"evidence": evidence}

    def revoke_intelligence_source(self, source: IntelSource, requested_by: str) -> dict[str, Any]:
        """Revoke a source Legal withdrew: audited first (a purge that fails half-way still leaves the
        decision on record), then unapproved and its records and vectors purged, whatever the switch says.
        Evidence already copied onto scenarios and plans stays."""
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        self._audit.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_REVOKED,
            admin_actor(requested_by),
            target,
            after={"approved": False},
        )
        purged = self._purge(source, existing_only=not self._settings.external_intelligence_enabled)
        return {"source": source, "records_purged": purged}

    def approve_intelligence_source(self, source: IntelSource, requested_by: str) -> dict[str, Any]:
        """Approve a revoked source again (409 while the env master is off): its health starts blank, the
        approval is audited and its refresh queued; `refresh_job_id` is None when a refresh was already queued
        or the run-time switch is off (either picks the source up later)."""
        if not self._settings.external_intelligence_enabled:
            raise Conflict(IntelRefreshMessage.SWITCH_OFF)
        self._feeds.update_intel_feed_approval(source, True)
        target = audit_target(AuditTarget.EXTERNAL_INTELLIGENCE_SOURCE, str(source))
        self._audit.create_audit_record(
            AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_APPROVED,
            admin_actor(requested_by),
            target,
            after={"approved": True},
        )
        return {"source": source, "refresh_job_id": self._queue_refresh(requested_by, source)}

    def _queue_refresh(self, requested_by: str, source: IntelSource | None = None) -> str | None:
        """Queue a refresh and return its job id; None when one is already queued or the switch is off."""
        try:
            return self.create_intelligence_refresh(requested_by, source)["job_id"]
        except Conflict:
            return None  # one is already queued or running and does the work, or the switch is off

    def _purge(self, source: IntelSource, existing_only: bool) -> int:
        """Unapprove the source (so no refresh writes it again), delete its records and cached vectors and
        rebuild the index so every process drops it; return the records deleted. `existing_only` (the master
        switch off) changes only an existing source row and builds and publishes nothing. A failed rebuild
        does not undo the purge: the keeper keeps trying."""
        self._feeds.update_intel_feed_approval(source, False, create=not existing_only)
        purged = self._records.delete(source=source)
        self._vectors.delete_vectors_used_only_by(source)
        if not existing_only:
            with suppress(Exception):  # the keeper logged it and tries again after a pause
                self._keeper.rebuild_index().result()
        return purged


def _flags(state: SwitchState) -> dict[str, bool]:
    """The two switches, as the audit row records them."""
    return {"env_enabled": state.env_enabled, "runtime_enabled": state.runtime_enabled}
