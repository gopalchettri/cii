"""Process-wide singletons: one MongoDB client, one SQL engine, one library cache … per process."""

import functools
import threading
from collections.abc import Callable


class singleton[T]:  # lower case on purpose: it is used as a decorator, `@singleton def get_x() -> X`
    """Decorates a zero-argument builder: the first call builds the value, every later call returns it.

    Not functools.lru_cache: it takes no lock while it builds, so threads calling at the same moment each
    build their own copy. A worker's 10 job threads starting together each made a library cache (with its own
    SQL checker thread and SQL pool), and every extra copy lived until the pod restarted. Here concurrent
    first callers wait for ONE build; a failed build stores nothing, so the next call tries again."""

    def __init__(self, build: Callable[[], T]) -> None:
        functools.update_wrapper(self, build)
        self._build = build
        self._lock = threading.Lock()
        self._built: list[T] = []  # empty until built (a list, so a built value may be anything)

    def __call__(self) -> T:
        if not self._built:
            with self._lock:
                if not self._built:
                    self._built.append(self._build())
        return self._built[0]

    def is_built(self) -> bool:
        return bool(self._built)
