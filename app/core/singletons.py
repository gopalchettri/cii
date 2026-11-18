"""Process-wide singletons: one MongoDB client, one SQL engine, one library cache … per process."""

import functools
import threading
from collections.abc import Callable


class singleton[T]:  # lower case on purpose: it is used as a decorator, `@singleton def get_x() -> X`
    """The first call builds the value under a lock (lru_cache would build once per racing thread)."""

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
