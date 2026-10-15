"""The worker's intelligence jobs: the evidence request built from a stored threat and the frozen context, the
scheduled and the admin refresh, the warm-up that never fails a start, and the plan's stamp."""

import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import Collection, EvidenceLimits, IntelSource, Status
from app.core.database import get_mongodb
from app.data_access.admin_jobs import AdminJobRecords
from app.search.external_intelligence.corpus_builder import CorpusBuilder
from app.worker import lifecycle
from app.worker.external_intelligence import warm_up as warm_up_module
from app.worker.external_intelligence.evidence_request_builder import EvidenceRequestBuilder
from app.worker.external_intelligence.refresh_task import refresh_external_intelligence, run_refresh_job
from app.worker.external_intelligence.relevance_corpus import RelevanceCorpus
from app.worker.external_intelligence.warm_up import (
    follow_active_snapshot,
    start_following_active_snapshot,
    warm_up_intelligence,
)
from tests.external_intelligence.conftest import Intel
from tests.external_intelligence.evidence_fakes import technique_doc
from tests.planner_samples import CONTEXT, system_row

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _threat(**changes: Any) -> dict[str, Any]:
    return {
        "key": "lib:1",
        "type": {"id": 1, "name": "Tampering with firmware"},
        "name": "Unauthorised firmware update",
        "reason": "Vendor sessions could push firmware. Mail ops@grid.example. " + "x" * 2000,
        "systems": [321],
    } | changes


def test_the_request_text_is_type_name_and_reason_only_redacted_and_cut() -> None:
    request = EvidenceRequestBuilder(CONTEXT).build(_threat())
    assert request.text.startswith(
        "Threat: Tampering with firmware: Unauthorised firmware update\nReason: Vendor"
    )
    assert "ops@grid.example" not in request.text and len(request.text) <= EvidenceLimits.QUERY_MAX_CHARS
    assert "Grid Control Centre" not in request.text  # the asset enters through the filter, not the text


def test_the_recorded_products_come_from_the_asset_row_and_the_threats_systems() -> None:
    context = CONTEXT.__class__(
        asset=CONTEXT.asset,
        asset_context=CONTEXT.asset_context | {"vendor_name": "Acme", "product_version": "1.2"},
        systems=[
            system_row(
                321,
                "SYS1",
                "SCADA server",
                technology_used=["Windows", "Siemens WinCC"],
                operating_system="Windows 10",
                firmware_version="9.0",
                category_code="OT",
            ),
            system_row(322, "SYS2", "Historian", technology_used=["OSIsoft PI"]),
        ],
    )
    request = EvidenceRequestBuilder(context).build(_threat())
    asset_row, system = request.recorded_products.rows  # only the threat's system: the Historian is not in it
    assert (asset_row.vendors, asset_row.versions) == (("Acme",), ("1.2",))
    assert system.products == ("Windows", "Siemens WinCC", "Windows 10") and system.versions == ("9.0",)
    assert "OT" in request.asset_types


def test_a_threat_naming_no_known_system_uses_every_system() -> None:
    request = EvidenceRequestBuilder(CONTEXT).build(_threat(systems=[999]))
    assert len(request.recorded_products.rows) == 1 + len(CONTEXT.systems)


def test_the_scheduled_refresh_runs_the_due_sources_only_while_the_switch_is_on(intel: Intel) -> None:
    refresh_external_intelligence()
    assert intel.refresher.calls == [("due", None)]
    intel.switch.enabled = False
    refresh_external_intelligence()
    assert len(intel.refresher.calls) == 1  # skipped


def _job(source: str | None = None) -> str:
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({})
    jobs = AdminJobRecords(get_mongodb())
    jobs.insert_active(
        {
            "_id": "j1",
            "kind": "intel_refresh",
            "status": Status.QUEUED,
            "requested_by": "op",
            "created_at": NOW,
            "source": source,
        }
    )
    return "j1"


def test_an_admin_refresh_of_one_source_is_recorded_on_its_job(intel: Intel) -> None:
    job_id = _job("cisa_kev")
    refresh_external_intelligence(job_id)
    assert intel.refresher.calls == [("one", IntelSource.CISA_KEV)]
    stored = AdminJobRecords(get_mongodb()).read(job_id)
    assert (stored["status"], stored["result"]) == (Status.DONE, {"source": "cisa_kev"})
    refresh_external_intelligence(job_id)  # a repeated message finds the job done
    assert len(intel.refresher.calls) == 1


def test_an_admin_refresh_while_the_switch_is_off_fails_its_job_with_the_reason(intel: Intel) -> None:
    intel.switch.enabled = False
    job_id = _job()
    refresh_external_intelligence(job_id)
    stored = AdminJobRecords(get_mongodb()).read(job_id)
    assert (
        stored["status"] == Status.FAILED
        and "off" in stored["error"]["message"]
        and intel.refresher.calls == []
    )


def test_a_failed_refresh_is_recorded_without_driver_details_then_raised(intel: Intel) -> None:
    class Broken:
        def refresh_due_sources(self, now: datetime) -> None:
            raise ValueError("mongodb://user:secret@host")

    intel.access._runtime.refresher = lambda: Broken()  # type: ignore[union-attr]
    job_id = _job()
    with pytest.raises(ValueError, match="secret"):
        run_refresh_job(job_id, AdminJobRecords(get_mongodb()), intel.access)
    stored = AdminJobRecords(get_mongodb()).read(job_id)
    assert stored["status"] == Status.FAILED and stored["error"] == {
        "code": "internal_error",
        "message": "ValueError",
    }


def test_the_warm_up_builds_in_the_background_only_while_on_and_never_fails(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[bool] = []

    class Keeper:
        def rebuild_index(self) -> None:
            built.append(True)
            raise RuntimeError("the store is down")

    monkeypatch.setattr(warm_up_module, "get_evidence_index_keeper", lambda: Keeper())
    warm_up_intelligence(intel.access)  # raises inside, swallowed
    assert built == [True]
    intel.switch.enabled = False
    warm_up_intelligence(intel.access)
    assert built == [True]


class _Intervals(threading.Event):
    """A stop event whose wait reports `count` intervals passed, then that the worker stops."""

    def __init__(self, count: int) -> None:
        super().__init__()
        self.count = count

    def wait(self, timeout: float | None = None) -> bool:
        self.count -= 1
        return self.count < 0


def test_the_worker_follows_the_active_snapshot_every_interval_only_while_on(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G242 (run 45b8c63b): the writer's first search after a reload got the old index, as nothing asked the
    keeper before it; now each interval asks, and one failed ask never ends the following."""
    asked: list[bool] = []

    class Keeper:
        def current_index(self) -> None:
            asked.append(True)
            if len(asked) == 1:
                raise RuntimeError("the store is down")

    monkeypatch.setattr(warm_up_module, "get_evidence_index_keeper", lambda: Keeper())
    follow_active_snapshot(intel.access, _Intervals(3))
    assert len(asked) == 3
    intel.switch.enabled = False
    follow_active_snapshot(intel.access, _Intervals(2))
    assert len(asked) == 3


def test_a_ready_worker_starts_one_follower_and_only_with_the_master_switch_on(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    followed: list[object] = []
    follower = lambda access, stop: followed.append(access)  # noqa: E731 - the thread's stand-in target
    monkeypatch.setattr(warm_up_module, "follow_active_snapshot", follower)
    thread = start_following_active_snapshot(intel.access)
    assert thread is not None and thread.daemon
    thread.join(5)
    assert followed == [intel.access]
    started: list[bool] = []
    monkeypatch.setattr(lifecycle, "warm_up_intelligence", lambda: None)
    monkeypatch.setattr(lifecycle, "start_following_active_snapshot", lambda: started.append(True))
    lifecycle.warm_up_external_intelligence()
    assert started == [True]
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    assert start_following_active_snapshot(intel.access) is None


def test_the_plan_is_stamped_with_the_snapshot_it_ranked_with_only_while_on(intel: Intel) -> None:
    """G238: one read gives the techniques and the snapshot they belong to; the plan records that snapshot."""
    relevance = _Relevance({"snapshot_id": "snap-1", "source_versions": {"cisa_kev": "v1"}})
    access = intel.access
    access._relevance = lambda: relevance  # type: ignore[method-assign]
    near, stamp = access.plan_intel([], CONTEXT)
    assert (near, stamp) == ({}, {"intel_snapshot_id": "snap-1", "intel_sources": {"cisa_kev": "v1"}})
    intel.switch.enabled = False
    assert access.plan_intel([], CONTEXT) == ({}, {}) and relevance.reads == 1


def test_planning_never_waits_and_a_failed_read_plans_without_the_tie_break(intel: Intel) -> None:
    class Broken:
        def current(self) -> Any:
            raise ConnectionError("store down")

    intel.access._relevance = Broken  # type: ignore[method-assign]
    assert intel.access.plan_intel([], CONTEXT) == ({}, {})


class _Relevance:
    def __init__(self, active: dict[str, Any]) -> None:
        self.active, self.reads = active, 0

    def current(self) -> tuple[Any, dict[str, Any]]:
        self.reads += 1
        return CorpusBuilder().build_corpus([technique_doc("T1")]), self.active


class _Records:
    def __init__(self) -> None:
        self.docs, self.reads = [technique_doc("T1")], 0

    def stream_current_records(self, sources: list[IntelSource], kind: Any) -> list[dict[str, Any]]:
        self.reads += 1
        assert set(sources) == {IntelSource.ATTACK_ENTERPRISE, IntelSource.ATTACK_ICS} and kind == "technique"
        return list(self.docs)


class _Pointer:
    def __init__(self) -> None:
        self.active: dict[str, Any] = {"snapshot_id": "snap-1"}

    def read_active_snapshot(self) -> dict[str, Any]:
        return self.active


class _Feeds:
    def list_approved_sources(self) -> list[IntelSource]:
        return list(IntelSource)


def test_planning_reads_the_techniques_again_only_when_a_newer_snapshot_is_published() -> None:
    """G238 (run 0ffdeabd planned with the old copy; a first plan waited up to 2 minutes): no wait, and never
    the old data. The same pointer: the copy in memory, no record read. Another pointer: read again."""
    records, pointer = _Records(), _Pointer()
    relevance = RelevanceCorpus(records, pointer, _Feeds())  # type: ignore[arg-type]
    first, _ = relevance.current()
    assert relevance.current()[0] is first and records.reads == 1
    records.docs.append(technique_doc("T2"))
    pointer.active = {"snapshot_id": "snap-2"}
    newer, active = relevance.current()
    assert records.reads == 2 and newer is not first and active["snapshot_id"] == "snap-2"
    assert {hit.external_id for hit in newer.hits} == {"T1", "T2"}


def test_no_attack_technique_stored_plans_without_the_tie_break_keeps_the_stamp_and_reads_once(
    intel: Intel,
) -> None:
    """Review 2026-10-14: the ATT&CK sources revoked, the other feeds on: the plan still names the snapshot
    the writer searches, ranks without the tie-break, and the empty answer is kept (not read per plan)."""
    records, pointer = _Records(), _Pointer()
    records.docs = []
    relevance = RelevanceCorpus(records, pointer, _Feeds())  # type: ignore[arg-type]
    intel.access._relevance = lambda: relevance  # type: ignore[method-assign]
    assert intel.access.plan_intel([], CONTEXT) == ({}, {"intel_snapshot_id": "snap-1", "intel_sources": {}})
    assert relevance.current()[0] is None and records.reads == 1
