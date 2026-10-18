"""Job-control rules: what a working run is shown as, when a cancel found nothing to stop, and the answer to
a click that lost the race with its run's delete."""

from app.core.constants import ConflictReason, JobControlMessage, JobKind, Status, TaskName
from app.core.exceptions import Conflict

_WORKING = (Status.QUEUED, Status.RUNNING)


def run_job_kind_and_status(status: str, task: str | None) -> tuple[JobKind, str]:
    """A run's job kind and shown status: finding threats or writing scenarios while its job is queued or
    running, else matching its scenarios' controls (shown running)."""
    if status not in _WORKING:
        return JobKind.CONTROLS, Status.RUNNING
    return (JobKind.THREATS if task == TaskName.FIND_THREATS else JobKind.SCENARIOS), status


def check_run_cancel_stopped_something(session_id: str, job_stopped: bool, controls_cancelled: int) -> None:
    """409 nothing_to_cancel when the cancel stopped neither the run's job nor any control matching."""
    if not job_stopped and not controls_cancelled:
        message = JobControlMessage.NOTHING_TO_CANCEL.format(session_id=session_id)
        raise Conflict(message, reason=ConflictReason.NOTHING_TO_CANCEL)


def run_being_deleted(session_id: str) -> Conflict:
    """409 run_being_deleted: the run is being deleted (a next set, a regenerate or a plan request)."""
    message = JobControlMessage.BEING_DELETED.format(session_id=session_id)
    return Conflict(message, reason=ConflictReason.RUN_BEING_DELETED)
