"""A process singleton is built once, even when threads ask for it at the same moment."""

import threading
import time

import pytest

from app.core.singletons import singleton


def test_concurrent_first_callers_get_one_instance() -> None:
    """Before (functools.lru_cache): 8 threads calling together built 8 objects; a worker's job threads each
    built a library cache with its own SQL checker thread and pool, kept until the pod restarted."""
    built: list[int] = []
    start = threading.Barrier(8)

    @singleton
    def get_thing() -> object:
        built.append(1)
        time.sleep(0.05)
        return object()

    results: list[object] = []

    def call() -> None:
        start.wait()
        results.append(get_thing())

    threads = [threading.Thread(target=call) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert len(built) == 1 and len({id(result) for result in results}) == 1


def test_a_failed_build_stores_nothing_and_the_next_call_tries_again() -> None:
    attempts: list[int] = []

    @singleton
    def get_thing() -> str:
        attempts.append(1)
        if len(attempts) == 1:
            raise ConnectionError("store down at start-up")
        return "ready"

    with pytest.raises(ConnectionError):
        get_thing()
    assert not get_thing.is_built()
    assert get_thing() == "ready" and get_thing.is_built() and len(attempts) == 2
