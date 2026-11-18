"""The control-links job: each MITRE ATT&CK mitigation linked to library controls, after an import and on an
admin's request."""

import uuid

from celery import Task
from celery.exceptions import Ignore

from app import ai
from app.core.clock import utc_now
from app.core.constants import CONTROL_LINKS_JOB_KIND, ControlLinkMessage, ControlLinks, ErrorCode, Status, TaskName
from app.core.exceptions import job_error_of
from app.crud.admin_jobs import get_admin_job_repository
from app.domain.intel.control_links import LinkTools, is_linking_locked, link_mitigations_to_controls
from app.search.service import get_library_search
from app.worker.celery_app import celery_app, current_worker
from app.worker.lease_renewal import keep_lease_alive


@celery_app.task(name=TaskName.LINK_MITIGATIONS, bind=True)
def link_mitigations(self: Task, job_id: str | None = None) -> None:
    """Celery task: an admin's preparation (`job_id`), or the one after an import, under a job record it makes."""
    if job_id is None:
        job_id = uuid.uuid4().hex
        job = {"_id": job_id, "kind": CONTROL_LINKS_JOB_KIND, "status": Status.QUEUED, "created_at": utc_now()}
        job["requested_by"] = ControlLinks.AFTER_IMPORT
        # Another preparation is active, or an ended one still holds the lock: it may have listed the graph
        # before this import, so this one runs after it.
        if is_linking_locked() or get_admin_job_repository().create_admin_job(job) != job_id:
            raise self.retry(countdown=ControlLinks.WAIT_TURN_SECONDS)
    run_control_links_job(job_id)


def prepare_control_links() -> dict[str, int] | None:
    """One linking run on the current library with the app's own models; None when another run holds the lock."""
    tools = LinkTools(
        get_library_search().snapshot(wait=True), ai.rerank.get_rerank_model(), ai.chat.get_scenario_chat_model()
    )
    return link_mitigations_to_controls(tools)


def run_control_links_job(job_id: str) -> None:
    """Run the preparation of a job record: its counts are its result; its cancel stops it at the next mitigation."""
    jobs = get_admin_job_repository()
    if not jobs.update_admin_job_running(job_id, utc_now(), **current_worker()):
        return  # done, failed or taken over already: a late or repeated message
    try:
        # A heartbeat refused (the job was cancelled or abandoned) sets the lost signal the linking checks.
        with keep_lease_alive(job_id, lambda: jobs.renew_admin_job(job_id, utc_now())):
            counts = prepare_control_links()
    except Exception as exc:
        if not jobs.update_admin_job_finished(job_id, utc_now(), error=job_error_of(exc)):
            raise Ignore from exc  # cancelled or abandoned meanwhile: that outcome stands
        raise
    busy = {"code": ErrorCode.CONFLICT, "message": ControlLinkMessage.BUSY.value}
    jobs.update_admin_job_finished(job_id, utc_now(), result=counts, error=busy if counts is None else None)
