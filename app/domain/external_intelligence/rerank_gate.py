"""The process-wide limit on evidence reranks, always taken before the AI slot so the two never deadlock. A
wait that ends is Unavailable (that request goes without evidence); a lost lease ends it too."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from app.core.constants import ErrorMessage, RerankGateLimits
from app.core.exceptions import Unavailable
from app.core.lease_signal import raise_if_lease_lost


class RerankGate:
    """A bounded number of places for evidence reranks; a waiter checks its job's lease as it waits."""

    def __init__(
        self,
        size: int,
        wait_seconds: float | None = RerankGateLimits.GATE_WAIT_SECONDS,
        check_every: float = RerankGateLimits.CHECK_EVERY_SECONDS,
    ) -> None:
        """`size` places; `wait_seconds` None: no fixed clock, a wait ends only with a lost lease."""
        self._places = threading.BoundedSemaphore(size)
        self._wait_seconds = wait_seconds
        self._check_every = check_every

    @contextmanager
    def hold_place(self) -> Iterator[None]:
        """Hold one place of the gate for the block."""
        self._wait_for_place()
        try:
            yield
        finally:
            self._places.release()

    def _wait_for_place(self) -> None:
        """Takes a place as soon as one frees; between checks, LeaseLost for a stopped job (it spends nothing
        more) and Unavailable once the gate's wait limit has passed."""
        raise_if_lease_lost()
        until = None if self._wait_seconds is None else time.monotonic() + self._wait_seconds
        while True:
            step = self._check_every if until is None else min(self._check_every, until - time.monotonic())
            if self._places.acquire(timeout=max(step, 0.0)):
                return
            raise_if_lease_lost()
            if until is not None and time.monotonic() >= until:
                raise Unavailable(ErrorMessage.RERANK_BUSY.format(seconds=round(self._wait_seconds or 0)))


def rerank_gate_for(rerank_base_url: str) -> RerankGate:
    """The gate for the reranker in use: a remote one (a base URL) gets RERANKS_AT_ONCE places and a timed
    wait, so it never takes every AI slot from the writer; a local CPU model one place and an untimed wait,
    since its queue always moves, however slowly."""
    if rerank_base_url:
        return RerankGate(RerankGateLimits.RERANKS_AT_ONCE)
    return RerankGate(RerankGateLimits.LOCAL_RERANKS_AT_ONCE, wait_seconds=None)
