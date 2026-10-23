"""An intelligence import's "stop now" check (POST /v1/admin/jobs/{job_id}/cancel): the admin job sets it,
the refresh asks it before each source and NVD before each request, so a cancelled import stops within one
request.

A ContextVar, as app/core/lease_signal.py: outside an admin job (the hourly import) nothing is cancelled."""

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar


def _go_on() -> bool:
    return True


_KEEP_GOING: ContextVar[Callable[[], bool]] = ContextVar("intel_import_keep_going", default=_go_on)


@contextmanager
def import_cancel_check(keep_going: Callable[[], bool]) -> Iterator[None]:
    """Inside this block, `keep_going()` says whether the import may go on (false: its job was cancelled)."""
    token = _KEEP_GOING.set(keep_going)
    try:
        yield
    finally:
        _KEEP_GOING.reset(token)


def import_cancelled() -> bool:
    """True once the running import's job was cancelled; never outside an admin job."""
    return not _KEEP_GOING.get()()
