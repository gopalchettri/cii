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


def test_a_method_patched_on_a_singletons_object_is_the_classes_again_after_undo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Before: pytest's undo put the old method back on the object itself, where it hid every later patch of the
    class: test_controls_fixes' spy on the sessions repository saw no read after test_d51_idempotency."""

    class Thing:
        limit = 3

        def read(self) -> str:
            return "real"

    @singleton
    def get_thing() -> Thing:
        return Thing()

    monkeypatch.setattr(get_thing(), "read", lambda: "fake")
    monkeypatch.setattr(get_thing(), "limit", 9)
    assert (get_thing().read(), get_thing().limit) == ("fake", 9)
    monkeypatch.undo()
    assert vars(get_thing()) == {} and (get_thing().read(), get_thing().limit) == ("real", 3)
    monkeypatch.setattr(Thing, "read", lambda self: "spied")
    assert get_thing().read() == "spied"
