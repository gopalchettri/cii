"""The on/off switch: env master AND runtime flag, cached, an outage keeps the last value, audited."""

import threading
from datetime import UTC, datetime

import pytest

from app.core.constants import AuditAction, Collection, IntelDocId, IntelLimits, SwitchTiming
from app.core.database import get_mongodb
from app.core.exceptions import MONGO_UNAVAILABLE_ERRORS
from app.services.external_intelligence.switch import ExternalIntelligenceSwitch

LATER = datetime(2026, 10, 12, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class MemoryFlags:
    def __init__(self, stored=None) -> None:
        self.stored, self.reads, self.down = stored, 0, False

    def read_runtime_flag(self):
        self.reads += 1
        if self.down:
            raise MONGO_UNAVAILABLE_ERRORS[0]("down")
        return self.stored

    def write_runtime_flag(self, enabled: bool, changed_by: str, now: datetime) -> None:
        if self.down:
            raise MONGO_UNAVAILABLE_ERRORS[0]("down")
        self.stored = (enabled, now, changed_by)


def _audit_count() -> int:
    audit = get_mongodb()[Collection.AUDIT]
    return audit.count_documents({"action": AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED})


def test_on_by_default_and_the_environment_master_always_wins() -> None:
    assert ExternalIntelligenceSwitch(MemoryFlags(), True).is_enabled()
    flags = MemoryFlags((True, LATER, "admin"))
    off = ExternalIntelligenceSwitch(flags, False)
    assert not off.is_enabled() and flags.reads == 0  # the store is not even read
    assert not ExternalIntelligenceSwitch(MemoryFlags((False, LATER, "a")), True).is_enabled()


def test_the_flag_is_read_once_per_period_and_a_change_shows_at_once_here() -> None:
    clock, flags = Clock(), MemoryFlags()
    switch = ExternalIntelligenceSwitch(flags, True, clock)
    for _ in range(20):
        switch.is_enabled()
    assert flags.reads == 1
    before = _audit_count()
    state = switch.change_runtime_flag(False, "admin-1")
    assert not switch.is_enabled() and (state.changed_by, state.runtime_enabled) == ("admin-1", False)
    assert flags.stored[0] is False and _audit_count() == before + 1
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    flags.stored = (True, LATER, "other-pod")  # another pod turned it on again
    assert switch.is_enabled() and flags.reads == 2


def test_a_store_outage_keeps_the_last_value() -> None:
    clock, flags = Clock(), MemoryFlags((False, LATER, "a"))
    switch = ExternalIntelligenceSwitch(flags, True, clock)
    assert not switch.is_enabled()
    flags.down = True
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    assert not switch.is_enabled()
    flags.down, flags.stored = False, (True, LATER, "a")
    clock.now += IntelLimits.SWITCH_CACHE_SECONDS + 1
    assert switch.is_enabled()


def test_with_no_value_yet_an_outage_reads_off_and_is_asked_again_soon() -> None:
    clock, flags = Clock(), MemoryFlags()
    flags.down = True
    switch = ExternalIntelligenceSwitch(flags, True, clock)
    assert not switch.is_enabled()
    flags.down = False
    clock.now += SwitchTiming.RETRY_AFTER_OUTAGE_SECONDS + 1
    assert switch.is_enabled()


def test_a_change_that_cannot_be_stored_changes_nothing_and_audits_nothing() -> None:
    clock, flags = Clock(), MemoryFlags()
    switch = ExternalIntelligenceSwitch(flags, True, clock)
    assert switch.is_enabled()
    flags.down = True
    before = _audit_count()
    with pytest.raises(MONGO_UNAVAILABLE_ERRORS[0]):
        switch.change_runtime_flag(False, "admin")
    assert switch.is_enabled() and _audit_count() == before


def test_a_read_that_began_before_a_change_never_overwrites_it() -> None:
    clock = Clock()
    started, finish = threading.Event(), threading.Event()

    class SlowFlags(MemoryFlags):
        def read_runtime_flag(self):
            value = self.stored
            started.set()
            finish.wait(5)
            return value

    switch = ExternalIntelligenceSwitch(SlowFlags((True, LATER, "a")), True, clock)
    seen = []
    reader = threading.Thread(target=lambda: seen.append(switch.is_enabled()))
    reader.start()
    assert started.wait(5)
    switch.change_runtime_flag(False, "admin")  # lands while the stale read is in flight
    finish.set()
    reader.join()
    assert not switch.is_enabled()


def test_the_id_of_the_switch_document_is_the_contract_one() -> None:
    assert IntelDocId.SWITCH == "switch"
