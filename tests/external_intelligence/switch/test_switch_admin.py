"""The admin over the REAL switch and stores: one audit row and one log line per change, nothing read or
created while the master switch is off, the revoke audited before its purge, and the approval route."""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from structlog.testing import capture_logs

from app import container
from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    Collection,
    IntelKind,
    IntelLimits,
    IntelSource,
    LogEvent,
)
from app.core.database import get_mongodb
from app.core.exceptions import Conflict
from app.data_access.external_intelligence.intel_feed_repository import IntelFeedRepository
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.models.external_intelligence.intel_record import IntelRecord
from tests.external_intelligence.evidence_fakes import MemoryKeeper
from tests.external_intelligence.fakes import intelligence_service

KEV = IntelSource.CISA_KEV
NOW = datetime(2026, 10, 12, tzinfo=UTC)
INTEL_COLLECTIONS = (
    Collection.INTEL,
    Collection.EXTERNAL_FEED_STATUS,
    Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS,
)


class Untouched:
    """A store that must be neither read nor written: any use fails the test."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the store was used: {name}")


class Flags:
    def __init__(self) -> None:
        self.stored: tuple[bool, datetime, str] | None = None

    def get(self, fields: Any = None, **where: Any) -> dict[str, Any] | None:
        if self.stored is None:
            return None
        return {"enabled": self.stored[0], "changed_at": self.stored[1], "changed_by": self.stored[2]}

    def save(self, record: dict[str, Any], only_if: Any = None) -> bool:
        self.stored = (record["enabled"], record["changed_at"], record["changed_by"])
        return True


class NoVectors:
    def delete_vectors_used_only_by(self, source: IntelSource) -> int:
        return 0


def _audit(action: AuditAction) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.AUDIT].find({"action": action}))


def _admin(monkeypatch: pytest.MonkeyPatch, *, env: bool, switch=None, **stores: Any):
    """The service over `stores` (the others Untouched) and the real audit; the refreshes it queues are
    recorded, not started."""
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", env)
    untouched = ("feeds", "records", "snapshots", "vectors", "admin_jobs", "index_keeper")
    parts = {name: Untouched() for name in untouched} | stores
    admin = intelligence_service(switch=switch or IntelligenceSwitch(Flags(), lambda: env), **parts)  # type: ignore[arg-type]
    started: list[tuple[str, IntelSource | None]] = []

    def start(requested_by: str, source: IntelSource | None = None) -> dict[str, Any]:
        started.append((requested_by, source))
        return {"job_id": "job-1", "status": "queued"}

    monkeypatch.setattr(admin, "create_intelligence_refresh", start)
    return admin, started


@pytest.fixture
def real_stores() -> Iterator[tuple[IntelRecordRepository, IntelFeedRepository]]:
    db = get_mongodb()
    for name in INTEL_COLLECTIONS:
        db[name].drop()
    records = container.get_intel_record_repository()
    yield records, container.get_intel_feed_repository()
    for name in INTEL_COLLECTIONS:
        db[name].drop()
    records.create_indexes()  # the suite's other tests expect them


def test_one_put_writes_exactly_one_audit_row_and_one_log_line(monkeypatch: pytest.MonkeyPatch) -> None:
    admin, refreshes = _admin(monkeypatch, env=True)
    before = len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED))
    with capture_logs() as logs:
        admin.update_intelligence_switch_state(False, "op-1")
    rows = _audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED)
    assert len(rows) == before + 1
    assert rows[-1]["actor"]["user_id"] == "op-1"
    assert rows[-1]["before"] == {"env_enabled": True, "runtime_enabled": True}
    assert rows[-1]["after"] == {"env_enabled": True, "runtime_enabled": False}
    assert [log["event"] for log in logs].count(LogEvent.EXTERNAL_INTELLIGENCE_SWITCH_CHANGED) == 1
    admin.update_intelligence_switch_state(True, "op-1")  # turning it on queues one refresh, still one row
    assert len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SWITCHED)) == before + 2
    assert refreshes == [("op-1", None)]


def test_with_the_master_switch_off_the_switch_answers_without_touching_the_store(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin, _ = _admin(
        monkeypatch, env=False, switch=IntelligenceSwitch(Untouched(), env_enabled=lambda: False)
    )
    state = admin.get_intelligence_switch_state()
    assert (state["env_enabled"], state["effective"]) == (False, False)
    with pytest.raises(Conflict):
        admin.update_intelligence_switch_state(True, "op")


def test_a_revoke_with_the_master_switch_off_creates_nothing_and_deletes_what_exists(
    monkeypatch: pytest.MonkeyPatch, real_stores
) -> None:
    records, feeds = real_stores
    keeper = MemoryKeeper()
    admin, _ = _admin(
        monkeypatch, env=False, records=records, feeds=feeds, vectors=NoVectors(), index_keeper=keeper
    )
    db = get_mongodb()
    revoked = admin.revoke_intelligence_source(KEV, "op")
    assert revoked == {"source": KEV, "records_purged": 0}  # a store never created
    assert not set(INTEL_COLLECTIONS) & set(db.list_collection_names()) and keeper.rebuilds == 0
    feeds.create_missing_intel_feeds()  # it was on once: data exists
    record = IntelRecord(KEV, "CVE-1", IntelKind.VULNERABILITY, "IT", "t", "x", "https://x", "v")
    records.save_intel_records([record], [], NOW)
    assert admin.revoke_intelligence_source(KEV, "op")["records_purged"] == 1
    assert not bool(feeds.count(_id=KEV, approved=True)) and records.count(sources=[KEV], current=True) == 0
    assert (
        Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS not in db.list_collection_names() and keeper.rebuilds == 0
    )


def test_a_revoke_is_audited_before_its_purge_so_a_failed_purge_leaves_the_decision_on_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Failing:
        def update_intel_feed_approval(self, source: IntelSource, approved: bool, *, create: bool) -> None:
            raise RuntimeError("the store went away half-way")

    admin, _ = _admin(monkeypatch, env=True, feeds=Failing())
    before = len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_REVOKED))
    with pytest.raises(RuntimeError):
        admin.revoke_intelligence_source(KEV, "op-9")
    row = _audit(AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_REVOKED)[-1]
    assert len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_REVOKED)) == before + 1
    assert row["actor"]["user_id"] == "op-9" and row["target"]["id"] == KEV


def test_approving_a_source_again_blanks_it_audits_and_queues_a_refresh_of_that_source(
    monkeypatch: pytest.MonkeyPatch, real_stores
) -> None:
    records, feeds = real_stores
    feeds.create_missing_intel_feeds()
    feeds.update_intel_feed_approval(KEV, False)
    admin, refreshes = _admin(monkeypatch, env=True, feeds=feeds)
    before = len(_audit(AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_APPROVED))
    assert admin.approve_intelligence_source(KEV, "op-2") == {"source": KEV, "refresh_job_id": "job-1"}
    assert bool(feeds.count(_id=KEV, approved=True)) and refreshes == [("op-2", KEV)]
    row = _audit(AuditAction.EXTERNAL_INTELLIGENCE_SOURCE_APPROVED)
    assert len(row) == before + 1 and row[-1]["actor"]["user_id"] == "op-2"
    assert feeds.claim_intel_feed_refresh(KEV, NOW, NOW)  # claimable again


def test_the_approval_is_refused_while_the_master_switch_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    admin, refreshes = _admin(monkeypatch, env=False)  # the stores are Untouched
    with pytest.raises(Conflict):
        admin.approve_intelligence_source(KEV, "op")
    assert refreshes == [] and IntelLimits.BATCH_SIZE
