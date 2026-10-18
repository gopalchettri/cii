"""A job's "your lease is lost" signal (G214): its lease renewer sets it when a renewal finds the record no
longer the job's (its owner cancelled or deleted the run, or another delivery took the job over), and every AI
call reads it first, so a stopped job makes no more AI calls: within one renewal (Lease.RENEW_EVERY_SECONDS)
of the cancel, not at its next save minutes later, and with no extra database read.

A ContextVar: the job's pool threads run in a copy of its context (domain/shared/parallel.py), so they read
the same signal; outside a job (the API, a plan request's top-up) there is none and nothing is checked."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from app.core.exceptions import LeaseLost

_SIGNAL: ContextVar[tuple[str, threading.Event] | None] = ContextVar("lease_lost_signal", default=None)


@contextmanager
def lease_lost_signal(record_id: str) -> Iterator[threading.Event]:
    """The signal of the job on `record_id`, for its whole run: set it once its lease is lost."""
    lost = threading.Event()
    token = _SIGNAL.set((record_id, lost))
    try:
        yield lost
    finally:
        _SIGNAL.reset(token)


def raise_if_lease_lost() -> None:
    """LeaseLost when the job this code runs for has lost its lease; nothing outside a job."""
    signal = _SIGNAL.get()
    if signal is not None and signal[1].is_set():
        raise LeaseLost(signal[0])
