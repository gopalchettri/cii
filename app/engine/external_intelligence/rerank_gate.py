"""The process-wide limit on evidence reranking.

Every evidence rerank holds one place of this gate for its call. The gate is always taken BEFORE the AI slot
(the slot is taken inside the rerank call), never the other way round, and nothing else is held while waiting
for it, so the two cannot deadlock. A waiter checks its job's lease as it waits: a cancelled job stops.

Its places and its wait follow the reranker in use (G218):
- remote (UAT, the proxy): RERANKS_AT_ONCE places, so many users' batches never take every AI slot from the
  scenario writer's chat calls; a wait ends after GATE_WAIT_SECONDS (a proxy that is down must not hold the
  scenarios up), or sooner at the caller's own deadline.
- local (the laptop's CPU model, dev only): one place, its real capacity (it predicts one at a time, G199). A
  wait has no fixed clock, since that queue always moves, however slowly: only the caller's own deadline or a
  lost lease ends it. A fixed 60 s gave up on a moving queue: run 0a84b002 wrote 2 scenarios of each 6
  without evidence while the model was still answering (its first answer, the model's load, took 106 s).
A wait that ends is Unavailable: that request goes without evidence, and the batch goes on."""

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from app.ai.common import seconds_left
from app.core.config import get_settings
from app.core.constants import ErrorMessage, RerankGateLimits
from app.core.exceptions import Unavailable
from app.core.lease_signal import raise_if_lease_lost
from app.core.singletons import singleton


class RerankGate:
    def __init__(
        self,
        size: int,
        wait_seconds: float | None = RerankGateLimits.GATE_WAIT_SECONDS,
        check_every: float = RerankGateLimits.CHECK_EVERY_SECONDS,
    ) -> None:
        """`wait_seconds` None: no fixed clock (the local model): a wait ends only at the caller's deadline or
        with a lost lease."""
        self._places = threading.BoundedSemaphore(size)
        self._wait_seconds = wait_seconds
        self._check_every = check_every

    @contextmanager
    def hold_place(self) -> Iterator[None]:
        self._wait_for_place()
        try:
            yield
        finally:
            self._places.release()

    def _wait_for_place(self) -> None:
        """Takes a place as soon as one frees; between checks, LeaseLost for a stopped job (it spends nothing
        more) and Unavailable once the wait's limit (the gate's, or the caller's deadline) has passed."""
        raise_if_lease_lost()
        limits = [limit for limit in (self._wait_seconds, seconds_left()) if limit is not None]
        until = time.monotonic() + min(limits) if limits else None
        while True:
            step = self._check_every if until is None else min(self._check_every, until - time.monotonic())
            if self._places.acquire(timeout=max(step, 0.0)):
                return
            raise_if_lease_lost()
            if until is not None and time.monotonic() >= until:
                raise Unavailable(ErrorMessage.RERANK_BUSY.format(seconds=round(min(limits))))


def rerank_gate_for(rerank_base_url: str) -> RerankGate:
    """The gate for the reranker in use: the proxy (a base URL) or the laptop's CPU model (none, dev only)."""
    if rerank_base_url:
        return RerankGate(RerankGateLimits.RERANKS_AT_ONCE)
    return RerankGate(RerankGateLimits.LOCAL_RERANKS_AT_ONCE, wait_seconds=None)


@singleton
def get_rerank_gate() -> RerankGate:
    return rerank_gate_for(get_settings().rerank_base_url)
