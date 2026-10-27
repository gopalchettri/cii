"""A job's lease kept alive while its work runs (app/worker/jobs.py runs the work): renewed from a background
thread while the job keeps checking its signal, and handed back to the queue when its worker stops."""

import contextlib
import contextvars
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Protocol

import structlog

from app.core.clock import utc_now
from app.core.constants import Lease, LogEvent, Status, TaskName, Worker
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, LeaseLost
from app.core.lease_signal import LeaseSignal, lease_lost_signal, raise_if_lease_lost
from app.data_access.jobs.job_repository import JobLease
from app.worker.celery_app import send_job
from app.worker.heartbeat import mark_worker_hung

log = structlog.get_logger(__name__)

#: The jobs this worker runs now, each with its task and a copy of its context (its log fields, request id).
_running: dict[JobLease, tuple[str, contextvars.Context]] = {}


class RenewableLease(Protocol):
    """A lease keep_lease_alive renews: a run's job lease, or one scenario's control lease."""

    record_id: str

    def renew(self) -> bool: ...


@contextmanager
def keep_lease_alive(lease: RenewableLease) -> Generator[None, None, None]:
    """Renew the lease every Lease.RENEW_EVERY_SECONDS while the work runs, from a background thread. A
    renewal that finds the lease lost (a cancel), or a job that made no lease check for Lease.STALL_SECONDS
    (hung: the reaper then takes it over), sets the job's signal: its next AI call raises LeaseLost
    (core/lease_signal.py), as its fenced writes do once the lease is gone."""
    stopped = threading.Event()
    with lease_lost_signal(lease.record_id) as lost:
        renewer = threading.Thread(  # in the job's context: its lines keep the task, module and request id
            target=contextvars.copy_context().run,
            args=(_renew_until_stopped, lease, lost, stopped),
            name=f"lease-{lease.record_id}",
            daemon=True,
        )
        renewer.start()
        try:
            yield
        finally:
            stopped.set()
            renewer.join()


def _renew_until_stopped(lease: RenewableLease, lost: LeaseSignal, stopped: threading.Event) -> None:
    """Renews until the work ends or the lease is lost. Python cannot stop a thread: one still running
    Lease.HUNG_AFTER_SECONDS after its lease was lost marks its worker hung, and the pod restarts."""
    while not stopped.wait(Lease.RENEW_EVERY_SECONDS):
        if not _renewed_while_working(lease, lost):
            lost.set()  # no more AI calls; the work's next fenced write raises LeaseLost too
            if not stopped.wait(Lease.HUNG_AFTER_SECONDS):
                mark_worker_hung(lease.record_id)
            return


def _renewed_while_working(lease: RenewableLease, lost: LeaseSignal) -> bool:
    """One renewal: False once the lease is lost, or when the job made no lease check for STALL_SECONDS."""
    if (silent := time.monotonic() - lost.checked_at) >= Lease.STALL_SECONDS:
        log.warning(LogEvent.JOB_STALLED, record_id=lease.record_id, seconds=round(silent))
        return False
    try:
        return lease.renew()
    except Exception:  # noqa: BLE001 — a store blip must not end renewing; the next round retries
        log.warning(LogEvent.JOB_LEASE_RENEW_FAILED, record_id=lease.record_id, exc_info=True)
        return True


@contextmanager
def handed_back_at_shutdown(task: str, lease: JobLease) -> Generator[None, None, None]:
    """While the work runs, a stopping worker can hand the job back (hand_back_running_jobs)."""
    _running[lease] = (task, contextvars.copy_context())
    try:
        yield
    finally:
        del _running[lease]


def hand_back_running_jobs(after_seconds: float = 0) -> None:
    """After `after_seconds` (time for running jobs to finish), queues every job still running here again."""
    time.sleep(after_seconds)
    for lease, (task, context) in _running.copy().items():
        context.run(_hand_back, task, lease)


def _hand_back(task: str, lease: JobLease) -> None:
    """The job queued again and sent now, with the attempt this delivery used given back; nothing when the job
    is no longer this delivery's or its signal is set (a stalled job's attempt counts: the reaper takes it).
    The old delivery then stops at its next AI call or write (LeaseLost)."""
    given_back = {
        "status": Status.QUEUED,
        "job.due_at": utc_now(),
        "job.lease_until": None,
        "job.attempts": lease.attempts - 1,
        "job.task_id": None,
        "job.worker": None,
        "job.retry": None,
    }
    with contextlib.suppress(LeaseLost, *MONGO_UNAVAILABLE_ERRORS):  # down: the reaper re-queues it later
        raise_if_lease_lost()
        lease.update_job(given_back)
        log.info(LogEvent.JOB_HANDED_BACK, record_id=lease.record_id, attempt=lease.attempts)
        send_job(TaskName(task), lease.record_id, lease.epoch, priority=Worker.NEXT_STAGE_PRIORITY)
