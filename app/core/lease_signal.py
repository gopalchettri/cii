"""A job's "your lease is lost" signal: its lease renewer sets it when a renewal finds the record no
longer the job's (its owner cancelled or deleted the run, or another delivery took the job over), and every AI
call reads it first, so a stopped job makes no more AI calls: within one renewal (Lease.RENEW_EVERY_SECONDS)
of the cancel, not at its next save minutes later, and with no extra database read.

A ContextVar: the job's pool threads run in a copy of its context (domain/shared/parallel.py), so they read
the same signal; outside a job (the API, a plan request's top-up) there is none and nothing is checked. A
lease taken inside a job (a plan job mapping one scenario's controls) adds its signal to the job's: both are
checked, the job's first."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from app.core.exceptions import LeaseLost

_SIGNALS: ContextVar[tuple[tuple[str, threading.Event], ...]] = ContextVar("lease_lost_signal", default=())


@contextmanager
def lease_lost_signal(record_id: str) -> Iterator[threading.Event]:
    """The signal of the lease on `record_id`, inside any enclosing one: set it once the lease is lost."""
    lost = threading.Event()
    token = _SIGNALS.set((*_SIGNALS.get(), (record_id, lost)))
    try:
        yield lost
    finally:
        _SIGNALS.reset(token)


def raise_if_lease_lost() -> None:
    """LeaseLost naming the outermost lost lease this code runs under; nothing outside a job."""
    for record_id, lost in _SIGNALS.get():
        if lost.is_set():
            raise LeaseLost(record_id)
