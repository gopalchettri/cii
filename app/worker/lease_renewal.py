"""A lease kept alive by a background thread while its work runs, and given back when its worker stops."""

import contextlib
import contextvars
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager

import structlog

from app.core.constants import Lease, LogEvent
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, LeaseLost
from app.core.lease_signal import lease_lost_signal, raise_if_lease_lost

log = structlog.get_logger(__name__)

#: The leases a stopping worker gives back, by signal: each one's give-back and its work's context.
_held: dict[threading.Event, tuple[Callable[[], bool], contextvars.Context]] = {}
#: Set once this stopping worker starts giving its leases back: a lease lost from then on was handed back.
handing_back = threading.Event()


@contextmanager
def keep_lease_alive(
    record_id: str, renew: Callable[[], bool], give_back: Callable[[], bool] | None = None
) -> Generator[None, None, None]:
    """Call `renew` every Lease.RENEW_EVERY_SECONDS from its own thread while the work runs; False sets the
    job's lost signal. `give_back` frees the lease when the worker stops."""
    stopped = threading.Event()
    with lease_lost_signal(record_id) as lost:
        renewer = threading.Thread(  # in the job's context: its lines keep the task, module and request id
            target=contextvars.copy_context().run,
            args=(_renew_until_stopped, record_id, renew, lost, stopped),
            name=f"lease-{record_id}",
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


def _renew_until_stopped(
    record_id: str, renew: Callable[[], bool], lost: threading.Event, stopped: threading.Event
) -> None:
    while not stopped.wait(Lease.RENEW_EVERY_SECONDS):
        try:
            renewed = renew()
        except Exception:  # noqa: BLE001 — a store blip must not end renewing; the next round retries
            log.warning(LogEvent.JOB_LEASE_RENEW_FAILED, record_id=record_id, exc_info=True)
            continue
        if not renewed:
            lost.set()  # no more AI calls; the work's next fenced write raises LeaseLost too
            return


def hand_back_running_jobs(after_seconds: float = 0) -> None:
    """After `after_seconds`, give back every lease still held here; its work stops at its next check."""
    time.sleep(after_seconds)
    handing_back.set()
    for lost, (give_back, context) in _held.copy().items():
        if context.run(_given_back, give_back):
            lost.set()


def _given_back(give_back: Callable[[], bool]) -> bool:
    with contextlib.suppress(LeaseLost, *MONGO_UNAVAILABLE_ERRORS):
        raise_if_lease_lost()
        return give_back()
    return False
