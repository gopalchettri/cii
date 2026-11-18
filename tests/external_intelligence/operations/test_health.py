"""Health: each source, pending sources, snapshot, switch."""

from collections.abc import Callable
from datetime import timedelta
from types import ModuleType

import pytest

from app.core.config import get_settings
from app.core.constants import FeedStatus, IntelSource
from app.schemas.intel_records import SourceHealth, SwitchState
from tests.external_intelligence.evidence_fakes import NOW, MemoryFeeds, MemoryKeeper, MemoryPointer
from tests.external_intelligence.fakes import intelligence_service

ENT, ICS = IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS


class FixedSwitch:
    def state(self) -> SwitchState:
        return SwitchState(True, False, NOW, "admin")


@pytest.fixture(autouse=True)
def env_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """The env master switch on."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)


@pytest.fixture(name="admin_over")
def admin_over_fixture(monkeypatch: pytest.MonkeyPatch) -> Callable[..., ModuleType]:
    """The admin module over the given parts, with the fixed switch."""
    return lambda **parts: intelligence_service(monkeypatch, switch=FixedSwitch(), **parts)


def _health(admin_over: Callable[..., ModuleType], feeds: MemoryFeeds, pointer: MemoryPointer) -> dict:
    service = admin_over(feeds=feeds, snapshots=pointer, index_keeper=MemoryKeeper())
    return service.get_intelligence_health()


def _fresh(source: IntelSource, hours: float) -> SourceHealth:
    return SourceHealth(source, FeedStatus.OK, "c", "v", 5, NOW, NOW - timedelta(hours=hours))


def test_health_shows_each_source_the_snapshot_and_the_switch(admin_over: Callable[..., ModuleType]) -> None:
    feeds, pointer = MemoryFeeds([ENT, ICS]), MemoryPointer()
    feeds.health = {ENT: _fresh(ENT, 1), ICS: _fresh(ICS, 1000)}
    pointer.active = {"snapshot_id": "snap-1", "checksum": "c"}
    report = _health(admin_over, feeds, pointer)
    assert (report["snapshot_id"], len(report["sources"])) == ("snap-1", 2)
    assert report["switch"]["runtime_enabled"] is False and report["switch"]["effective"] is False


def test_a_never_run_source_is_pending_while_the_other_has_data(admin_over: Callable[..., ModuleType]) -> None:
    feeds, pointer = MemoryFeeds([ENT, ICS]), MemoryPointer()
    feeds.health = {ENT: _fresh(ENT, 1), ICS: SourceHealth(ICS)}
    report = _health(admin_over, feeds, pointer)
    assert report["pending_sources"] == ["mitre_attack_ics"] and not report["no_data"]


def test_when_no_source_ever_succeeded_there_is_no_data(admin_over: Callable[..., ModuleType]) -> None:
    feeds, pointer = MemoryFeeds([ENT, ICS]), MemoryPointer()
    feeds.health = {ENT: SourceHealth(ENT), ICS: SourceHealth(ICS, FeedStatus.FAILED, last_attempt_at=NOW)}
    report = _health(admin_over, feeds, pointer)
    # no pointer, empty index
    assert report["no_data"] and report["snapshot_id"] is None
    assert set(report["pending_sources"]) == {ENT, ICS}
