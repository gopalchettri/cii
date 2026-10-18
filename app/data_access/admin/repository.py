"""The admin collections: admin jobs, API clients, the audit trail, AI calls, query and library vectors."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

import pymongo
import structlog
from pymongo import ReplaceOne, UpdateOne
from pymongo.collection import Collection as MongoCollection

from app.core import metrics
from app.core.constants import (
    AdminJobMessage,
    AdminJobs,
    AiLimits,
    Audit,
    AuditAction,
    Cache,
    Collection,
    EmbeddingCorpus,
    ErrorCode,
    LogEvent,
    Status,
    Timeouts,
)
from app.core.exceptions import DuplicateRecord
from app.data_access.base import MongoRepository, Record

log = structlog.get_logger(__name__)

_DAY_SECONDS = int(timedelta(days=1).total_seconds())


def _retired_fields(now: datetime) -> Record:
    """A retired vector's stamp and its expiry Cache.RETIRED_VECTOR_DAYS later."""
    return {"retired_at": now, "expires_at": now + timedelta(days=Cache.RETIRED_VECTOR_DAYS)}


class AdminJobRepository(MongoRepository):
    """tsg_admin_jobs: one active job per kind (a unique index over the `active` records); an ended job loses
    `active` and stays as history."""

    def create_admin_job(self, job: Record) -> str | None:
        """Creates `job` (with its created_at) as the active job of its kind in tsg_admin_jobs and returns its
        id; else the id of the active job of that kind. One still unfinished AdminJobs.STALE_AFTER_SECONDS
        after its creation (its worker died, its message was lost) is failed and replaced."""
        stale_before = job["created_at"] - timedelta(seconds=AdminJobs.STALE_AFTER_SECONDS)
        abandoned = AdminJobMessage.ABANDONED.format(seconds=AdminJobs.STALE_AFTER_SECONDS)
        error = {"code": ErrorCode.JOB_ABANDONED, "message": abandoned}
        stale = {"kind": job["kind"], "active": True, "created_at": {"$lt": stale_before}}
        if self._create_active(job) or (
            self._finish(stale, Status.FAILED, job["created_at"], error=error) and self._create_active(job)
        ):
            return job["_id"]
        active = self.get(("_id",), kind=job["kind"], active=True)
        if active is None and self._create_active(job):  # the active job finished in between
            return job["_id"]
        return active["_id"] if active else None

    def update_admin_job_running(self, job_id: str, now: datetime) -> bool:
        """Marks a queued tsg_admin_jobs job running; False when it is no longer queued (a late or repeated
        message, so a redelivered copy never runs a second build)."""
        changes = {"status": Status.RUNNING, "started_at": now}
        return self.update(changes, _id=job_id, active=True, status=Status.QUEUED) > 0

    def update_admin_job_finished(
        self, job_id: str, now: datetime, *, result: Record | None = None, error: Record | None = None
    ) -> bool:
        """Ends an active tsg_admin_jobs job, done with its result or failed with its error, once; False when
        it was no longer active (taken over as abandoned: it keeps the outcome it already has)."""
        which = {"_id": job_id, "active": True}
        if error is not None:
            return self._finish(which, Status.FAILED, now, error=error)
        return self._finish(which, Status.DONE, now, result=result)

    def _create_active(self, job: Record) -> bool:
        """Inserts `job` as active; False when a job of its kind is still active."""
        try:
            self.create(job | {"active": True})
        except DuplicateRecord:
            return False
        return True

    def _finish(self, which: Record, status: Status, now: datetime, **fields: Any) -> bool:
        """Ends the active job `which` matches; True when there was one."""
        ended = {"$set": {"status": status, "finished_at": now, **fields}, "$unset": {"active": ""}}
        return self.collection.update_one(which, ended).matched_count > 0


class ApiClientRepository(MongoRepository):
    """tsg_api_clients: unique key hashes, unique names among active clients."""

    def revoke_api_client(self, client_id: str, revoked_by: str, revoked_at: datetime) -> Record | None:
        """Deactivates the active tsg_api_clients client and returns it (no key hash); None when no active
        client has that id."""
        changes = {"active": False, "revoked_at": revoked_at, "revoked_by": revoked_by}
        return self.update_and_get(changes, fields="without_key_hash", _id=client_id, active=True)


class AuditRepository(MongoRepository):
    """tsg_audit: append-only; the TTL index deletes a record after Audit.KEEP_DAYS."""

    def create_audit_record(  # noqa: PLR0913 — the audit record's own fields
        self,
        action: AuditAction,
        actor: Record,
        target: Record,
        before: Record | None = None,
        after: Record | None = None,
        details: Record | None = None,
    ) -> None:
        """Appends one tsg_audit record after the action's own write succeeded, within
        Timeouts.RECORD_WRITE_SECONDS; a failure is logged and counted, never raised."""
        # Also a log line (Grafana shows the trail next to the logs); before/after stay in tsg_audit only.
        log.info(LogEvent.AUDIT_RECORDED, action=action, actor=actor, target=target)
        record = {
            "at": datetime.now(UTC),
            "action": action,
            "actor": actor,
            "target": target,
            "before": before,
            "after": after,
            "details": details,
            "request_id": structlog.contextvars.get_contextvars().get("request_id"),
        }
        try:
            with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):  # the answer is waiting: not the 30 s socket
                self.collection.insert_one(record)
        except Exception:  # noqa: BLE001 — the action already happened: an audit outage must not fail it
            metrics.AUDIT_FAILURES.inc()
            log.warning(LogEvent.AUDIT_WRITE_FAILED, action=action, target=target, exc_info=True)


class AiCallRepository(MongoRepository):
    """tsg_ai_calls: every write bounded by Timeouts.RECORD_WRITE_SECONDS (the answer is in hand)."""

    def create(self, record: Record) -> Any:
        """Inserts one tsg_ai_calls record within Timeouts.RECORD_WRITE_SECONDS."""
        with pymongo.timeout(Timeouts.RECORD_WRITE_SECONDS):
            return super().create(record)


class VectorRepository(MongoRepository):
    """A vector collection, each vector stored by its key as _id and expiring at its own expires_at (a query
    vector always, a library vector once retired); `ids=keys` finds the vectors with those keys."""

    def __init__(self, collection: str | MongoCollection, **options: Any) -> None:
        """The vector collection with its expiry and its `ids` condition."""
        super().__init__(collection, ttl=[("expires_at", 0)], conditions={"ids": _vector_ids}, **options)

    def save_vectors(self, vectors: list[Record]) -> None:
        """Writes each vector whole (one of the wrong size is replaced). Another worker storing the same text
        at the same moment is fine (an identical vector); any other write error is raised."""
        upserts = [ReplaceOne({"_id": vector["_id"]}, vector, upsert=True) for vector in vectors]
        self.bulk_write_skipping_duplicates(upserts, ordered=False)


class LibraryVectorRepository(VectorRepository):
    """tsg_embeddings: the library's vectors; one no row uses is retired, then expires."""

    def retire_unknown_vector_corpora(self) -> int:
        """Retires (never deletes) the tsg_embeddings vectors of a corpus this code does not know: during a
        rolling update a newer process's next build brings back what it uses. How many were retired."""
        known = [corpus.value for corpus in EmbeddingCorpus]
        unknown = {"corpus": {"$exists": True, "$nin": known}, "retired_at": {"$exists": False}}
        return self.collection.update_many(
            unknown, {"$set": _retired_fields(datetime.now(UTC))}
        ).modified_count

    def update_library_vector_corpus(
        self, corpus: EmbeddingCorpus, in_use: dict[str, list[Record]], stored: dict[str, Record]
    ) -> int:
        """Brings one corpus of tsg_embeddings in line with the library now: a vector in use (`in_use`: key ->
        rows using it; `stored`: what was read before embedding) lists exactly its rows and is not retired;
        every other vector of the corpus is retired. How many were retired. Two processes seeing different
        library versions for a moment are safe: the next build brings back a vector still in use."""
        changed = [
            UpdateOne(
                {"_id": key}, {"$set": {"sources": sources}, "$unset": {"retired_at": "", "expires_at": ""}}
            )
            for key, sources in in_use.items()
            if key in stored and (stored[key].get("sources") != sources or "retired_at" in stored[key])
        ]
        if changed:
            self.collection.bulk_write(changed, ordered=False)
        unused = {"corpus": corpus, "_id": {"$nin": list(in_use)}, "retired_at": {"$exists": False}}
        return self.collection.update_many(
            unused, {"$set": _retired_fields(datetime.now(UTC))}
        ).modified_count

    def count_library_vectors_made_since(self, since: datetime) -> dict[str, int]:
        """{corpus: tsg_embeddings vectors embedded at or after `since`}: one aggregation answered from the
        (created_at, corpus) index alone."""
        made = self.collection.aggregate(
            [
                {"$match": {"created_at": {"$gte": since}}},
                {"$group": {"_id": "$corpus", "count": {"$sum": 1}}},
            ]
        )
        return {found["_id"]: found["count"] for found in made}


def _vector_ids(keys: Iterable[str]) -> Record:
    """The vectors with these keys."""
    return {"_id": {"$in": list(set(keys))}}


admin_jobs = AdminJobRepository(
    Collection.ADMIN_JOBS,
    indexes=[
        {
            "keys": "kind",
            "unique": True,
            "partialFilterExpression": {"active": True},
            "name": "one_active_per_kind",
        }
    ],
    ttl=[("created_at", AdminJobs.KEEP_DAYS * _DAY_SECONDS)],
    field_lists={"without_active_flag": {"active": 0}},
    schema_version=1,
)
api_clients = ApiClientRepository(
    Collection.API_CLIENTS,
    indexes=[
        {"keys": "key_hash", "unique": True},
        {"keys": "name", "unique": True, "partialFilterExpression": {"active": True}},
    ],
    field_lists={"without_key_hash": {"key_hash": 0}},
    schema_version=1,
)
audit_records = AuditRepository(
    Collection.AUDIT,
    indexes=[{"keys": [("actor.entity_id", 1), ("at", -1)]}, {"keys": [("target.id", 1), ("at", -1)]}],
    ttl=[("at", Audit.KEEP_DAYS * _DAY_SECONDS)],
    schema_version=1,
)
ai_calls = AiCallRepository(
    Collection.AI_CALLS,
    indexes=[{"keys": [("task_id", 1), ("prompt_hash", 1)]}],  # find one job's AI calls
    ttl=[("created_at", AiLimits.CALL_RECORD_DAYS * _DAY_SECONDS)],
    schema_version=1,
)
query_vectors = VectorRepository(Collection.QUERY_VECTORS, schema_version=1)
library_vectors = LibraryVectorRepository(
    Collection.EMBEDDINGS,
    # a row's vectors now and before; the vectors made since (count_library_vectors_made_since)
    indexes=[{"keys": [("corpus", 1), ("sources.id", 1)]}, {"keys": [("created_at", 1), ("corpus", 1)]}],
    schema_version=1,
)
