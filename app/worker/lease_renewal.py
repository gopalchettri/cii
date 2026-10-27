"""A lease kept alive while its work runs (app/worker/jobs.py runs a job's work): renewed from a background
thread while the work keeps checking its signal, and given back when its worker stops."""

import contextlib
import contextvars
import threading
import time
from collections.abc import Callable, Generator
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

#: The leases held here that a stopping worker gives back, by signal: each one's give-back and a copy of its
#: work's context (its log fields, request id).
_held: dict[LeaseSignal, tuple[Callable[[], bool], contextvars.Context]] = {}


class RenewableLease(Protocol):
    """A lease keep_lease_alive renews: a run's job lease, or one scenario's control lease."""

    record_id: str

    def renew(self) -> bool: ...


@contextmanager
def keep_lease_alive(
    lease: RenewableLease, give_back: Callable[[], bool] | None = None
) -> Generator[None, None, None]:
    """Renew the lease every Lease.RENEW_EVERY_SECONDS while the work runs, from a background thread. A
    renewal that finds the lease lost (a cancel), or a job that made no lease check for Lease.STALL_SECONDS
    (hung: the reaper then takes it over), sets the job's signal: its next AI call raises LeaseLost
    (core/lease_signal.py), as its fenced writes do once the lease is gone. `give_back` frees the lease for
    another worker when this one stops (hand_back_running_jobs), True once it did."""
    stopped = threading.Event()
    with lease_lost_signal(lease.record_id) as lost:
        renewer = threading.Thread(  # in the job's context: its lines keep the task, module and request id
            target=contextvars.copy_context().run,
            args=(_renew_until_stopped, lease, lost, stopped),
            name=f"lease-{lease.record_id}",
            daemon=True,
        )
        renewer.start()
        if give_back is not None:
            _held[lost] = (give_back, contextvars.copy_context())
        try:
            yield
        finally:
            _held.pop(lost, None)
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


def hand_back_running_jobs(after_seconds: float = 0) -> None:
    """After `after_seconds` (time for running work to finish), gives back every lease still held here; its
    work then stops at its next lease check (an AI call or wait), not at its next renewal."""
    time.sleep(after_seconds)
    for lost, (give_back, context) in _held.copy().items():
        if context.run(_given_back, give_back):
            lost.set()


def _given_back(give_back: Callable[[], bool]) -> bool:
    """give_back(), unless the work's lease is lost already (a stalled job's attempt counts: the reaper takes
    it over); False when nothing was given back (the lease lost meanwhile, or the store down: it runs out)."""
    with contextlib.suppress(LeaseLost, *MONGO_UNAVAILABLE_ERRORS):
        raise_if_lease_lost()
        return give_back()
    return False


def give_job_back(task: str, lease: JobLease) -> bool:
    """The job queued again and sent now, with the attempt this delivery used given back; LeaseLost once the
    job is no longer this delivery's."""
    given_back = {
        "status": Status.QUEUED,
        "job.due_at": utc_now(),
        "job.lease_until": None,
        "job.attempts": lease.attempts - 1,
        "job.task_id": None,
        "job.worker": None,
        "job.retry": None,
    }
    lease.update_job(given_back)
    log.info(LogEvent.JOB_HANDED_BACK, record_id=lease.record_id, attempt=lease.attempts)
    send_job(TaskName(task), lease.record_id, lease.epoch, priority=Worker.NEXT_STAGE_PRIORITY)
    return True
