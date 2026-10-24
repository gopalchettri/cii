"""Background job of the library: keep the search indexes built (maintenance queue), every 30 minutes and
when an admin asks for it now (#18, an embeddings build with its own job record)."""

from typing import Any

from app.core.clock import utc_now
from app.core.constants import LIBRARY_OF_CORPUS, AuditAction, AuditTarget, Status, TaskName
from app.data_access.admin.admin_job_repository import AdminJobRepository
from app.data_access.admin.audit_repository import AuditRepository
from app.data_access.admin.embedding_repository import EmbeddingRepository
from app.domain.shared.audit import audit_target
from app.search.library_cache import LibraryCache
from app.search.service import LibrarySearch
from app.search.snapshot import LibrarySnapshot
from app.worker.celery_app import celery_app, current_worker
from app.worker.jobs import job_error_of


@celery_app.task(name=TaskName.BUILD_LIBRARY_INDEXES)
def build_library_indexes(job_id: str | None = None) -> None:
    """Compute vectors for new or edited library rows now (every Cache.LIBRARY_INDEXES_EVERY_SECONDS), so the
    first run after a library edit does not wait for them. Unchanged rows are read from the vector store.
    Waits for the build (searches never do), so a failed build fails this job and is counted. With `job_id`
    (an admin's build, #18) the job record says how it went."""
    from app import container

    if job_id is None:
        container.get_library_search().snapshot(wait=True)
        return
    run_embeddings_job(
        job_id,
        container.get_admin_job_repository(),
        container.get_library_cache(),
        container.get_library_search(),
        container.get_embedding_repository(),
        container.get_audit_repository(),
    )


def run_embeddings_job(
    job_id: str,
    jobs: AdminJobRepository,
    library: LibraryCache,
    search: LibrarySearch,
    vectors: EmbeddingRepository,
    audit: AuditRepository,
) -> None:
    """Reads the library now (an edit made a moment ago is built now, not after the next stamp check), builds
    every library's vectors, and records the row counts and how many vectors were made while it ran. A failure
    (SQL Server unreachable while reading the library included: never "done" on the old library) is recorded,
    then raised (counted like any failed job). Audited only when this job ended the record: one taken over as
    abandoned keeps that outcome."""
    started_at = utc_now()
    if not jobs.update_admin_job_running(job_id, started_at, **current_worker()):
        return  # done, failed or taken over already: a late or repeated message
    try:
        library.reload_if_library_changed()  # raises, unlike the background check: the job must say so
        snapshot = search.snapshot(wait=True)
        made = vectors.count_library_vectors_made_since(started_at)
    except Exception as exc:
        error = job_error_of(exc)
        if jobs.update_admin_job_finished(job_id, utc_now(), error=error):
            _audit_finished(audit, job_id, {"status": Status.FAILED, "error": error})
        raise
    result = {
        "counts": library_counts(snapshot),
        "newly_embedded": {name: made.get(corpus, 0) for corpus, name in LIBRARY_OF_CORPUS.items()},
    }
    if jobs.update_admin_job_finished(job_id, utc_now(), result=result):
        _audit_finished(audit, job_id, {"status": Status.DONE, **result})


def library_counts(snapshot: LibrarySnapshot) -> dict[str, int]:
    """How many rows each library holds now, each with its vector."""
    threat_library = snapshot.library.threat_library
    return {
        "threats": len(threat_library.threats),
        "threat_types": len(snapshot.threat_types),
        "actors": len(threat_library.actors),
        "controls": len(snapshot.library.control_library),
    }


def _audit_finished(audit: AuditRepository, job_id: str, after: dict[str, Any]) -> None:
    target = audit_target(AuditTarget.ADMIN_JOB, job_id)
    actor = {"system": TaskName.BUILD_LIBRARY_INDEXES}
    audit.create_audit_record(AuditAction.ADMIN_JOB_FINISHED, actor, target, after=after)
