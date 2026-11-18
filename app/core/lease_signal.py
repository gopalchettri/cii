"""A job's "your lease is lost" signal (a ContextVar), set by its renewer and read before every AI call."""

import threading
from collections.abc import Callable, Iterator
from concurrent import futures
from contextlib import contextmanager
from contextvars import Context, ContextVar, copy_context

from app.core.constants import AiLimits
from app.core.exceptions import LeaseLost

_SIGNALS: ContextVar[tuple[tuple[str, threading.Event], ...]] = ContextVar("lease_lost_signal", default=())
#: The name of the shared thread this code runs on (library or evidence indexes); None on a job's own threads.
_SHARED_WORK: ContextVar[str | None] = ContextVar("shared_work", default=None)


@contextmanager
def lease_lost_signal(record_id: str) -> Iterator[threading.Event]:
    """The signal of the lease on `record_id`, inside any enclosing one: set it once the lease is lost."""
    lost = threading.Event()
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
    """A daemon thread running `work` in the caller's context under no lease, as shared work."""
    context = context_without_lease()
    context.run(_SHARED_WORK.set, name)
    threading.Thread(target=context.run, args=(work, *args), name=name, daemon=True).start()


def shared_work() -> str | None:
    """The shared thread this code runs on (start_thread_without_lease's name), or None."""
    return _SHARED_WORK.get()


def raise_if_lease_lost() -> None:
    """LeaseLost naming the outermost lost lease this code runs under; nothing outside a job."""
    for record_id, lost in _SIGNALS.get():
        if lost.is_set():
            raise LeaseLost(record_id)


def wait_while_leased[Result](outcome: futures.Future[Result]) -> Result:
    """Wait for shared work, checking the job's lease every AiLimits.LEASE_CHECK_SECONDS."""
    while not futures.wait([outcome], timeout=AiLimits.LEASE_CHECK_SECONDS).done:
        raise_if_lease_lost()
    return outcome.result()
