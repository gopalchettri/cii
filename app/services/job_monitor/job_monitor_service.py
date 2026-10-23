"""GET /v1/admin/jobs: every job of every kind (runs, plans, mappings, intelligence refreshes, embeddings
builds) with its status, error, retry and worker, and each queue's backlog and workers online; one job by id;
and the cancel of an intelligence import or an embeddings build."""

from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.constants import (
    AuditAction,
    AuditTarget,
    Collection,
    ConflictReason,
    JobMonitorMessage,
    LogEvent,
    module_of,
)
from app.core.exceptions import Conflict, NotFound
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.jobs.job_repository import JobRepository
from app.domain.shared.audit import admin_actor, audit_target
from app.models.jobs.views import JobMonitor, MonitoredJob, QueueState, retry_notice_of

log = structlog.get_logger(__name__)


class JobMonitorService:
    def __init__(
        self,
        leased: dict[str, JobRepository],
        admin_jobs: AdminJobRepository,
        queues: Iterable[str],
        count_waiting: Callable[[str], int],
        count_workers: Callable[[Iterable[str]], dict[str, int]],
        audit: AuditRepository,
    ) -> None:
        self._leased, self._admin_jobs, self._queues = leased, admin_jobs, tuple(queues)
        self._count_waiting, self._count_workers, self._audit = count_waiting, count_workers, audit

    def get_job(self, job_id: str) -> MonitoredJob:
        """One job of any kind by its id (an admin job's job_id, or a run's, plan's or mapping's id); 404."""
        if (record := self._admin_jobs.get_any_admin_job(job_id)) is not None:
            return _admin_job(record)
        for collection, repository in self._leased.items():
            if (leased := repository.get_job_record(job_id)) is not None:
                return _leased_job(collection, leased)
        raise NotFound(JobMonitorMessage.NOT_FOUND.format(job_id=job_id))

    def cancel_job(self, job_id: str, actor: str) -> MonitoredJob:
        """Cancel a queued or running intelligence import or embeddings build: a queued one never starts, a
        running import stops at its next NVD request or source (what it read is kept, the next import
        continues), a running build finishes and its outcome is dropped. Audited. 409 for another module's
        job or one already ended."""
        job = self.get_job(job_id)
        if job.collection != Collection.ADMIN_JOBS:
            message = JobMonitorMessage.NOT_ADMIN_JOB.format(job_id=job_id, module=job.module)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
        if not self._admin_jobs.cancel_admin_job(job_id, datetime.now(UTC), actor):
            message = JobMonitorMessage.ALREADY_ENDED.format(job_id=job_id, status=job.status)
            raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)
        self._audit.create_audit_record(
            AuditAction.ADMIN_JOB_CANCELLED,
            admin_actor(actor),
            audit_target(AuditTarget.ADMIN_JOB, job_id),
            before={"status": job.status},
            after={"status": "cancelled", "kind": job.kind},
        )
        return self.get_job(job_id)

    def list_jobs(  # noqa: PLR0913 — the list's filters: each one is needed
        self, since: datetime, statuses: list[str], kind: str | None, limit: int, module: str | None = None
    ) -> JobMonitor:
        jobs = [
            _leased_job(collection, record)
            for collection, repository in self._leased.items()
            for record in repository.list_recent_jobs(since, statuses, kind, limit)
        ]
        jobs += [
            _admin_job(record)
            for record in self._admin_jobs.list_recent_admin_jobs(since, statuses, kind, limit)
        ]
        if module:
            jobs = [job for job in jobs if job.module == module]
        jobs.sort(key=lambda job: job.started_at or job.created_at or since, reverse=True)
        return JobMonitor(jobs=jobs[:limit], queues=self._queue_states())

    def _queue_states(self) -> dict[str, QueueState]:
        workers = self._count_workers(self._queues)
        return {
            queue: QueueState(waiting=self._waiting(queue), workers_online=workers.get(queue, 0))
            for queue in self._queues
        }

    def _waiting(self, queue: str) -> int | None:
        try:
            return self._count_waiting(queue)
        except Exception:  # noqa: BLE001 — the broker unreachable: the list still answers, the count is unknown
            log.warning(LogEvent.JOB_QUEUE_SIZE_UNKNOWN, queue=queue, exc_info=True)
            return None


def _leased_job(collection: str, record: dict[str, Any]) -> MonitoredJob:
    job = record.get("job") or {}
    status = record.get("status", "")
    return MonitoredJob(
        id=str(record["_id"]),
        module=module_of(job.get("task", "")),
        kind=job.get("task", ""),
        collection=collection,
        entity_id=record.get("entity_id"),
        status=status,
        retrying=retry_notice_of(status, job.get("retry")),
        attempts=job.get("attempts"),
        created_at=record.get("created_at"),
        started_at=job.get("started_at"),
        finished_at=record.get("finished_at"),
        error=job.get("error"),
        task_id=job.get("task_id"),
        worker=job.get("worker"),
    )


def _admin_job(record: dict[str, Any]) -> MonitoredJob:
    return MonitoredJob(
        id=str(record["_id"]),
        module=module_of(record.get("kind", "")),
        kind=record.get("kind", ""),
        collection=Collection.ADMIN_JOBS,
        status=record.get("status", ""),
        created_at=record.get("created_at"),
        started_at=record.get("started_at"),
        finished_at=record.get("finished_at"),
        error=record.get("error"),
        task_id=record.get("task_id"),
        worker=record.get("worker"),
    )
