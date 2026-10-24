"""A job's lease kept alive while its work runs (app/worker/jobs.py runs the work): renewed from a background
thread, and the job's signal set once the lease is lost or the job has run too long."""

import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from typing import Protocol

import structlog

from app.core.constants import Lease, LogEvent
from app.core.lease_signal import lease_lost_signal

log = structlog.get_logger(__name__)


class RenewableLease(Protocol):
    """A lease keep_lease_alive renews: a run's job lease, or one scenario's control lease."""

    record_id: str

    def renew(self) -> bool: ...


@contextmanager
def keep_lease_alive(lease: RenewableLease) -> Generator[None, None, None]:
    """Renew the lease every Lease.RENEW_EVERY_SECONDS while the work runs, from a background thread, for at
    most Lease.MAX_JOB_SECONDS: a hung job then loses its lease to the reaper, which counts the attempt. A
    renewal that finds the lease lost (a cancel), or the time limit, sets the job's signal: its next AI call
    raises LeaseLost (core/lease_signal.py), as its next fenced write does."""
    stopped = threading.Event()
    deadline = time.monotonic() + Lease.MAX_JOB_SECONDS

    def renew_until_stopped(lost: threading.Event) -> None:
        while not stopped.wait(Lease.RENEW_EVERY_SECONDS):
            if time.monotonic() >= deadline:
                log.warning(LogEvent.JOB_TOO_LONG, record_id=lease.record_id, seconds=Lease.MAX_JOB_SECONDS)
                lost.set()  # no more AI calls; its writes fail (LeaseLost) once the reaper takes the job over
                return
            try:
                if not lease.renew():
                    lost.set()  # no more AI calls; the work's next fenced write raises LeaseLost too
                    return
            except Exception:  # noqa: BLE001 — a store blip must not end renewing; the next round retries
                log.warning(LogEvent.JOB_LEASE_RENEW_FAILED, record_id=lease.record_id, exc_info=True)

    with lease_lost_signal(lease.record_id) as lost:
        renewer = threading.Thread(
            target=renew_until_stopped, args=(lost,), name=f"lease-{lease.record_id}", daemon=True
        )
        renewer.start()
        try:
            yield
        finally:
            stopped.set()
            renewer.join()
