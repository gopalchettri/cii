"""Turns at the laptop's CPU reranker, scenarios first (G222).

The local model predicts one call at a time (G199). Control mapping asks it about 40 controls per scenario
(minutes on a laptop CPU), while finding and writing scenarios ask about a handful; with first come, first
served, a next set waited behind mapping for many minutes (live 2026-10-13: an evidence call over 5 minutes).
So a waiting foreground call (finding or writing scenarios, a plan request's top-up) always goes before a
waiting background one (the control-mapping job, inside `background_reranks()`). Foreground calls are few and
short, so the background work always resumes. Only the local model takes turns: the proxy (UAT) answers calls
side by side under the AI slots."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

_BACKGROUND: ContextVar[bool] = ContextVar("background_reranks", default=False)


@contextmanager
def background_reranks() -> Iterator[None]:
    """The reranks inside are background work: they give way to any waiting foreground rerank."""
    token = _BACKGROUND.set(True)
    try:
        yield
    finally:
        _BACKGROUND.reset(token)


def reranks_in_background() -> bool:
    return _BACKGROUND.get()


class LocalTurns:
    """One prediction at a time; when the model frees, a waiting foreground call is served before any
    waiting background call."""

    def __init__(self) -> None:
        self._changed = threading.Condition()
        self._busy = False
        self._foreground_waiting = 0

    @contextmanager
    def turn(self) -> Iterator[None]:
        background = reranks_in_background()
        with self._changed:
            if not background:
                self._foreground_waiting += 1
            try:
                self._changed.wait_for(lambda: not (self._busy or (background and self._foreground_waiting)))
            finally:
                if not background:
                    self._foreground_waiting -= 1
            self._busy = True
        try:
            yield
        finally:
            with self._changed:
                self._busy = False
                self._changed.notify_all()
