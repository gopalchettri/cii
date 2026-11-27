"""The intelligence refresh job: beat's check of the saved schedule, and an admin's import."""

import threading

import structlog
from celery.exceptions import Ignore
from kombu.exceptions import OperationalError as BrokerUnavailable

from app.core.clock import utc_now
from app.core.config import get_settings
from app.core.constants import (
    ErrorCode,
    IntelLimits,
    IntelRefreshMessage,
    IntelSource,
    IntelWorkEvent,
    LogEvent,
    TaskName,
)
from app.core.exceptions import REDIS_UNAVAILABLE_ERRORS, job_error_of
from app.crud.admin_jobs import get_admin_job_repository
from app.domain.intel import refresh, schedule
from app.domain.intel.index import EvidenceIndexRefused, get_evidence_index_keeper
from app.domain.intel.switch import get_intelligence_switch
from app.worker.celery_app import celery_app, current_worker
from app.worker.lease_renewal import keep_lease_alive

log = structlog.get_logger(__name__)


@celery_app.task(name=TaskName.REFRESH_EXTERNAL_INTELLIGENCE)
def refresh_external_intelligence(job_id: str | None = None) -> None:
    """Celery task: without `job_id` it is beat's check, importing only when the saved schedule is due (the
    import runs with the external-intelligence switch off too: the MITRE run reads it, ADR-010)."""
    if job_id is not None:
        run_refresh_job(job_id)
    elif schedule.claim_due_run(now := utc_now()):
        failed = True
        try:
            failed = bool(refresh.refresh_all_sources(now).failed)
        finally:
            if failed:  # whole or for one source: due again within the hour, not at the next slot
                schedule.retry_claimed_run(now)
        _send_link_mitigations()


def _send_link_mitigations() -> None:
    """After every import: the links follow the graph and the library, and a linking that failed runs again."""
    try:
        celery_app.send_task(TaskName.LINK_MITIGATIONS)
    except (BrokerUnavailable, *REDIS_UNAVAILABLE_ERRORS):  # the import stands; the next import sends it again
        log.warning(LogEvent.CONTROL_LINKS_NOT_QUEUED, exc_info=True)


def run_refresh_job(job_id: str) -> None:
    """Run an admin's refresh of its one source, or of every one, whatever the schedule says."""
    jobs, now = get_admin_job_repository(), utc_now()
    if not jobs.update_admin_job_running(job_id, now, **current_worker()):
        return
    record = jobs.get(("source",), _id=job_id) or {}
    source = IntelSource(record["source"]) if record.get("source") else None
    try:
        with keep_lease_alive(job_id, lambda: jobs.renew_admin_job(job_id, utc_now()) or True):  # never lost
            if source is None:  # its cancel stops it before the next source
                summary = refresh.refresh_all_sources(now, keep_going=lambda: jobs.is_admin_job_active(job_id))
            else:
                summary = refresh.refresh_one_source(source, now)
    except Exception as exc:
        log.warning(IntelWorkEvent.REFRESH_JOB_FAILED, record_id=job_id, exc_info=True)
        if not jobs.update_admin_job_finished(job_id, utc_now(), error=job_error_of(exc)):
            raise Ignore from exc  # cancelled or abandoned meanwhile: that outcome stands
        raise
    # The data refresh stands; an index the AI could not rebuild is told beside it (with its reason).
    index_error = {"index_error": summary.index_error} if summary.index_error else {}
    failed = IntelRefreshMessage.SOURCES_FAILED.format(sources=", ".join(summary.failed))
    sources_failed = {"code": ErrorCode.UNAVAILABLE, "message": failed} if summary.failed else None
    outcomes = [
        {"source": item.source, "outcome": item.result, "new_data": item.new_data}
        | {"new_versions": item.new_versions, "retired": item.retired}
        for item in summary.sources
    ]  # the page says per source whether anything new arrived
    result = {"source": source, "sources": outcomes} | index_error
    jobs.update_admin_job_finished(job_id, utc_now(), result=result, error=sources_failed)
    _send_link_mitigations()


def warm_up_intelligence() -> None:
    """Build the evidence index while the switch is on, waiting at most (off: no keeper is built)."""
    try:
        if not get_intelligence_switch().is_on():
            log.info(IntelWorkEvent.WARM_UP_SKIPPED)
            return
        get_evidence_index_keeper().rebuild_index().result(timeout=IntelLimits.INDEX_AT_START_SECONDS)
    except Exception as exc:  # failed or late: the worker starts, a batch waits as for an outage
        if not (isinstance(exc, EvidenceIndexRefused) and exc.no_data):  # no data yet: the keeper said so
            log.warning(IntelWorkEvent.WARM_UP_FAILED, exc_info=True)


def start_following_active_snapshot() -> threading.Thread | None:
    """Start the daemon thread that keeps this process on the active snapshot."""
    if not get_settings().external_intelligence_enabled:
        return None
    try:
        thread = threading.Thread(
            target=follow_active_snapshot, args=(threading.Event(),), name="evidence-follow", daemon=True
        )
        thread.start()
    except Exception:  # a worker starts anyway; each search still follows the pointer itself
        log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
        return None
    return thread


def follow_active_snapshot(stop: threading.Event) -> None:
    """Until `stop` is set, ask the keeper for its index each interval while the switch is on."""
    while not stop.wait(IntelLimits.SWITCH_CACHE_SECONDS):
        try:
            if get_intelligence_switch().is_on():
                get_evidence_index_keeper().current_index()
        except Exception:  # the next interval asks again; the index in use keeps serving
            log.warning(IntelWorkEvent.FOLLOW_FAILED, exc_info=True)
