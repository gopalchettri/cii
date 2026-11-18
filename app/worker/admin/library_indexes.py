"""The library's search indexes, built every 30 minutes and on an admin's request (#18)."""

from typing import Any

from celery.exceptions import Ignore

from app.core.clock import utc_now
from app.core.constants import LIBRARY_OF_CORPUS, AuditAction, AuditTarget, Status, TaskName
from app.core.exceptions import job_error_of
from app.crud.admin_jobs import AdminJobRepository, get_admin_job_repository
from app.crud.audit import AuditRepository, get_audit_repository
from app.crud.embeddings import EmbeddingRepository, get_embedding_repository
from app.domain.shared.audit import audit_target
from app.search.library_cache import LibraryCache, get_library_cache
from app.search.service import LibrarySearch, get_library_search
from app.search.snapshot import LibrarySnapshot
from app.worker.celery_app import celery_app, current_worker
from app.worker.lease_renewal import keep_lease_alive


@celery_app.task(name=TaskName.BUILD_LIBRARY_INDEXES)
def build_library_indexes(job_id: str | None = None) -> None:
    """Build vectors for new or edited library rows; with `job_id` (an admin's build) its record says how."""

    if job_id is None:
        get_library_search().snapshot(wait=True)
        return
    run_embeddings_job(
        job_id,
        get_admin_job_repository(),
        get_library_cache(),
        get_library_search(),
        get_embedding_repository(),
        get_audit_repository(),
    )


def run_embeddings_job(
    job_id: str,
    jobs: AdminJobRepository,
    library: LibraryCache,
    search: LibrarySearch,
    vectors: EmbeddingRepository,
    audit: AuditRepository,
) -> None:
    """Reload the library, build its vectors and record the counts; a failure is recorded, then raised."""
    started_at = utc_now()
    if not jobs.update_admin_job_running(job_id, started_at, **current_worker()):
        return  # done, failed or taken over already: a late or repeated message
    try:
        with keep_lease_alive(job_id, lambda: jobs.renew_admin_job(job_id, utc_now()) or True):  # never lost
            library.reload_if_library_changed()  # raises, unlike the background check: the job must say so
            snapshot = search.snapshot(wait=True)
            made = vectors.count_library_vectors_made_since(started_at)
    except Exception as exc:
        error = job_error_of(exc)
        if not jobs.update_admin_job_finished(job_id, utc_now(), error=error):
            raise Ignore from exc  # cancelled or abandoned meanwhile: that outcome stands
        _audit_finished(audit, job_id, {"status": Status.FAILED, "error": error})
        raise
    result = {
        "counts": library_counts(snapshot),
        "newly_embedded": {name: made.get(corpus, 0) for corpus, name in LIBRARY_OF_CORPUS.items()},
    }
    if jobs.update_admin_job_finished(job_id, utc_now(), result=result):
        _audit_finished(audit, job_id, {"status": Status.DONE, **result})


def library_counts(snapshot: LibrarySnapshot) -> dict[str, int]:
    """How many rows each library holds now."""
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
