"""A job's "your lease is lost" signal: its lease renewer sets it when a renewal finds the record no
longer the job's (its owner cancelled or deleted the run, or another delivery took the job over), and every AI
call reads it first, so a stopped job makes no more AI calls: within one renewal (Lease.RENEW_EVERY_SECONDS)
of the cancel, not at its next save minutes later, and with no extra database read.

A ContextVar: the job's pool threads run in a copy of its context (domain/shared/parallel.py), so they read
the same signal; outside a job (the API, a plan request's top-up) there is none and nothing is checked. A
lease taken inside a job (a plan job mapping one scenario's controls) adds its signal to the job's: both are
checked, the job's first. Each check also stamps the signal: the lease renewer reads how long ago the job
last checked, so a job that stops checking is known to be hung."""

import threading
import time
from collections.abc import Callable, Iterator
from concurrent import futures
from contextlib import contextmanager
from contextvars import Context, ContextVar, copy_context

from app.core.constants import AiLimits
from app.core.exceptions import LeaseLost


class LeaseSignal(threading.Event):
    """Set once the lease is lost; `checked_at` (time.monotonic) is the job's last check of it."""

    def __init__(self) -> None:
        super().__init__()
        self.checked_at = time.monotonic()


_SIGNALS: ContextVar[tuple[tuple[str, LeaseSignal], ...]] = ContextVar("lease_lost_signal", default=())


@contextmanager
def lease_lost_signal(record_id: str) -> Iterator[LeaseSignal]:
    """The signal of the lease on `record_id`, inside any enclosing one: set it once the lease is lost."""
    lost = LeaseSignal()
    token = _SIGNALS.set((*_SIGNALS.get(), (record_id, lost)))
    try:
        yield lost
    finally:
        _SIGNALS.reset(token)


def context_without_lease() -> Context:
    """A copy of the caller's context (its log fields) under no lease: for a thread every job shares."""
    context = copy_context()
    context.run(_SIGNALS.set, ())
    return context


def start_thread_without_lease(name: str, work: Callable[..., object], *args: object) -> None:
    """A daemon thread running `work` in a copy of the caller's context (its log fields) under no lease."""
    threading.Thread(target=context_without_lease().run, args=(work, *args), name=name, daemon=True).start()


def raise_if_lease_lost() -> None:
    """LeaseLost naming the outermost lost lease this code runs under; nothing outside a job."""
    now = time.monotonic()
    for record_id, lost in _SIGNALS.get():
        lost.checked_at = now  # the job still looks: it is working, not hung
        if lost.is_set():
            raise LeaseLost(record_id)


def wait_while_leased[Result](outcome: futures.Future[Result]) -> Result:
    """Waits for work another thread shares, checking the job's lease every AiLimits.LEASE_CHECK_SECONDS."""
    while not futures.wait([outcome], timeout=AiLimits.LEASE_CHECK_SECONDS).done:
        raise_if_lease_lost()
    return outcome.result()
