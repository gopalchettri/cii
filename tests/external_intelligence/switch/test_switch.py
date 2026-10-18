"""The on/off switch: env master AND runtime flag, cached, an outage keeps the last value."""

import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime

import pytest

from app.core.config import get_settings
from app.core.constants import AuditAction, Collection, IntelDocId, IntelLimits, SwitchTiming
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS, Unavailable
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from tests.external_intelligence.fakes import intelligence_service

LATER = datetime(2026, 10, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class MemoryFlags:
    def __init__(self, stored=None) -> None:
        self.stored, self.reads, self.down = stored, 0, False

    def get(self, fields=None, **where):
        self.reads += 1
        if self.down:
            raise MONGO_UNAVAILABLE_ERRORS[0]("down")
        return _switch_doc(self.stored)

    def save(self, record: dict, only_if=None) -> bool:
        if self.down:
            raise MONGO_UNAVAILABLE_ERRORS[0]("down")
        self.stored = (record["enabled"], record["changed_at"], record["changed_by"])
        return True


def _switch_doc(stored):
    """The switch document a (enabled, changed_at, changed_by) tuple stands for, or None."""
    if stored is None:
        return None
    return {"enabled": stored[0], "changed_at": stored[1], "changed_by": stored[2]}


def _audit_count() -> int:
    audit = get_mongodb()[Collection.AUDIT]
    return audit.count_documents({"action": AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED})


def _switch(flags: MemoryFlags, clock: Callable[[], float] = time.monotonic) -> IntelligenceSwitch:
    """The switch with the env master switch on."""
    return IntelligenceSwitch(flags, env_enabled=lambda: True, clock=clock)  # type: ignore[arg-type]


def test_on_by_default_and_the_environment_master_always_wins() -> None:
    assert _switch(MemoryFlags()).is_on()
    assert not _switch(MemoryFlags((False, LATER, "a"))).is_on()
    flags = MemoryFlags((True, LATER, "admin"))
    off = IntelligenceSwitch(flags, env_enabled=lambda: False)  # type: ignore[arg-type]
    assert not off.is_on(sure=True) and flags.reads == 0  # the store is not even read


def test_the_flag_is_read_once_per_period_and_a_change_shows_at_once_here() -> None:
    clock, flags = Clock(), MemoryFlags()
    switch = _switch(flags, clock)
    for _ in range(20):
        switch.is_on()
    assert flags.reads == 1
    state = switch.save(False, "admin-1")
    assert not switch.is_on() and (state.changed_by, state.runtime_enabled) == ("admin-1", False)
    assert flags.stored[0] is False
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    flags.stored = (True, LATER, "other-pod")  # another pod turned it on again
    assert switch.is_on() and flags.reads == 2


def test_a_store_outage_keeps_the_last_value() -> None:
    clock, flags = Clock(), MemoryFlags((False, LATER, "a"))
    switch = _switch(flags, clock)
    assert not switch.is_on()
    flags.down = True
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    assert not switch.is_on()
    flags.down, flags.stored = False, (True, LATER, "a")
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    assert switch.is_on()


def test_with_no_value_yet_an_outage_reads_off_and_is_asked_again_soon() -> None:
    clock, flags = Clock(), MemoryFlags()
    flags.down = True
    switch = _switch(flags, clock)
    assert not switch.is_on()
    with pytest.raises(Unavailable):  # in doubt: a writer that must be sure waits
        switch.is_on(sure=True)
    flags.down = False
    clock.now += SwitchTiming.RETRY_AFTER_OUTAGE_SECONDS + 1
    assert switch.is_on() and switch.state().known is True


def test_a_change_that_cannot_be_stored_changes_nothing_and_audits_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    clock, flags = Clock(), MemoryFlags()
    switch = _switch(flags, clock)
    service = intelligence_service(switch=switch, index_keeper=None)
    assert switch.is_on()
    flags.down = True
    before = _audit_count()
    with pytest.raises(MONGO_UNAVAILABLE_ERRORS[0]):
        service.update_intelligence_switch_state(False, "admin")
    assert switch.is_on() and _audit_count() == before


def test_a_read_that_began_before_a_change_never_overwrites_it() -> None:
    clock = Clock()
    started, finish = threading.Event(), threading.Event()

    class SlowFlags(MemoryFlags):
        def get(self, fields=None, **where):
            value = self.stored
            started.set()
            finish.wait(5)
            return _switch_doc(value)

    switch = _switch(SlowFlags((True, LATER, "a")), clock)
    seen = []
    reader = threading.Thread(target=lambda: seen.append(switch.is_on()))
    reader.start()
    assert started.wait(5)
    switch.save(False, "admin")  # lands while the stale read is in flight
    finish.set()
    reader.join()
    assert not switch.is_on()


def test_the_id_of_the_switch_document_is_the_contract_one() -> None:
    assert IntelDocId.SWITCH == "switch"
