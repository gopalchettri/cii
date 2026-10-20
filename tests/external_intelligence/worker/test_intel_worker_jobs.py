"""The worker's intelligence jobs: the evidence request built from a stored threat and the frozen context, the
scheduled and the admin refresh, and the warm-up that never fails a start."""

import threading
from datetime import UTC, datetime
from typing import Any

import pytest

from app import container
from app.core.config import get_settings
from app.core.constants import Collection, EvidenceLimits, IntelSource, Status
from app.core.database import get_mongodb
from app.worker import lifecycle
from app.worker.external_intelligence import warm_up as warm_up_module
from app.worker.external_intelligence.evidence_at_write import evidence_request
from app.worker.external_intelligence.refresh_task import refresh_external_intelligence, run_refresh_job
from app.worker.external_intelligence.warm_up import (
    follow_active_snapshot,
    start_following_active_snapshot,
    warm_up_intelligence,
)
from tests.external_intelligence.conftest import Intel
from tests.planner_samples import CONTEXT, system_row

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _admin_jobs() -> Any:
    return container.get_admin_job_repository()


def _threat(**changes: Any) -> dict[str, Any]:
    return {
        "key": "lib:1",
        "type": {"id": 1, "name": "Tampering with firmware"},
        "name": "Unauthorised firmware update",
        "reason": "Vendor sessions could push firmware. Mail ops@grid.example. " + "x" * 2000,
        "systems": [321],
    } | changes


def test_the_request_text_is_the_threats_type_and_name_only() -> None:
    """G268 (measured on run 89b47690): the relevance reason, written about the whole asset, pulled sources
    matching its words, not the threat's; the search text is the threat itself."""
    request = evidence_request(CONTEXT, _threat())
    assert request.text == "Threat: Tampering with firmware: Unauthorised firmware update"
    assert "Vendor" not in request.text and len(request.text) <= EvidenceLimits.QUERY_MAX_CHARS
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
    request = evidence_request(context, _threat())
    asset_row, system = request.recorded_products.rows  # only the threat's system: the Historian is not in it
    assert (asset_row.vendors, asset_row.versions) == (("Acme",), ("1.2",))
    assert system.products == ("Windows", "Siemens WinCC", "Windows 10") and system.versions == ("9.0",)
    assert "OT" in request.asset_types


def test_a_threat_naming_no_known_system_uses_every_system() -> None:
    request = evidence_request(CONTEXT, _threat(systems=[999]))
    assert len(request.recorded_products.rows) == 1 + len(CONTEXT.systems)


def test_the_scheduled_refresh_runs_the_due_sources_only_while_the_switch_is_on(intel: Intel) -> None:
    refresh_external_intelligence()
    assert intel.refresher.calls == [("due", None)]
    intel.switch.enabled = False
    refresh_external_intelligence()
    assert len(intel.refresher.calls) == 1  # skipped


def _job(source: str | None = None) -> str:
    get_mongodb()[Collection.ADMIN_JOBS].delete_many({})
    _admin_jobs().create(
        {
            "active": True,
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
    stored = _admin_jobs().get(_id=job_id)
    assert (stored["status"], stored["result"]) == (Status.DONE, {"source": "cisa_kev"})
    refresh_external_intelligence(job_id)  # a repeated message finds the job done
    assert len(intel.refresher.calls) == 1


def test_a_refresh_whose_index_the_ai_could_not_rebuild_is_done_and_says_why(intel: Intel) -> None:
    """Owner 2026-10-20: the data refresh stands (done), and the job tells the index error with its AI
    reason instead of reading as if all went well."""
    down = {"code": "unavailable", "message": "The AI service is down.", "reason": "ai_down"}
    intel.refresher.index_error = down
    job_id = _job("cisa_kev")
    refresh_external_intelligence(job_id)
    stored = _admin_jobs().get(_id=job_id)
    assert (stored["status"], stored["result"]) == (Status.DONE, {"source": "cisa_kev", "index_error": down})


def test_an_admin_refresh_runs_while_the_workers_cached_switch_still_reads_off(intel: Intel) -> None:
    """Turning the switch on queues a refresh the worker takes before its cached switch catches up."""
    intel.switch.enabled = False
    job_id = _job()
    refresh_external_intelligence(job_id)
    assert intel.refresher.calls == [("due", None)] and _admin_jobs().get(_id=job_id)["status"] == Status.DONE


def test_an_admin_refresh_while_the_master_switch_is_off_fails_its_job_with_the_reason(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    job_id = _job()
    refresh_external_intelligence(job_id)
    stored = _admin_jobs().get(_id=job_id)
    assert (
        stored["status"] == Status.FAILED
        and "off" in stored["error"]["message"]
        and intel.refresher.calls == []
    )


def test_a_failed_refresh_is_recorded_without_driver_details_then_raised(intel: Intel) -> None:
    class Broken:
        def refresh_due_sources(self, now: datetime) -> None:
            raise ValueError("mongodb://user:secret@host")

    job_id = _job()
    with pytest.raises(ValueError, match="secret"):
        run_refresh_job(job_id, _admin_jobs(), lambda: Broken())  # type: ignore[arg-type,return-value]
    stored = _admin_jobs().get(_id=job_id)
    assert stored["status"] == Status.FAILED and stored["error"] == {
        "code": "internal_error",
        "message": "ValueError",
    }


def test_the_warm_up_builds_in_the_background_only_while_on_and_never_fails(intel: Intel) -> None:
    built: list[bool] = []

    class Keeper:
        def rebuild_index(self) -> None:
            built.append(True)
            raise RuntimeError("the store is down")

    warm_up_intelligence(intel.switch, lambda: Keeper())  # type: ignore[arg-type,return-value]  # swallowed
    assert built == [True]
    intel.switch.enabled = False
    warm_up_intelligence(intel.switch, lambda: Keeper())  # type: ignore[arg-type,return-value]
    assert built == [True]


class _Intervals(threading.Event):
    """A stop event whose wait reports `count` intervals passed, then that the worker stops."""

    def __init__(self, count: int) -> None:
        super().__init__()
        self.count = count

    def wait(self, timeout: float | None = None) -> bool:
        self.count -= 1
        return self.count < 0


def test_the_worker_follows_the_active_snapshot_every_interval_only_while_on(intel: Intel) -> None:
    """G242 (run 45b8c63b): the writer's first search after a reload got the old index, as nothing asked the
    keeper before it; now each interval asks, and one failed ask never ends the following."""
    asked: list[bool] = []

    class Keeper:
        def current_index(self) -> None:
            asked.append(True)
            if len(asked) == 1:
                raise RuntimeError("the store is down")

    follow_active_snapshot(intel.switch, lambda: Keeper(), _Intervals(3))  # type: ignore[arg-type,return-value]
    assert len(asked) == 3
    intel.switch.enabled = False
    follow_active_snapshot(intel.switch, lambda: Keeper(), _Intervals(2))  # type: ignore[arg-type,return-value]
    assert len(asked) == 3


def test_a_ready_worker_starts_one_follower_and_only_with_the_master_switch_on(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    followed: list[object] = []
    follower = lambda switch, keeper, stop: followed.append(switch)  # noqa: E731 - the thread's stand-in target
    monkeypatch.setattr(warm_up_module, "follow_active_snapshot", follower)
    keeper = container.get_evidence_index_keeper  # the provider: never called here
    thread = start_following_active_snapshot(get_settings(), intel.switch, keeper)
    assert thread is not None and thread.daemon
    thread.join(5)
    assert followed == [intel.switch]
    started: list[bool] = []
    monkeypatch.setattr(lifecycle, "warm_up_intelligence", lambda *args: None)
    monkeypatch.setattr(lifecycle, "start_following_active_snapshot", lambda *args: started.append(True))
    lifecycle.warm_up_external_intelligence()
    assert started == [True]
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", False)
    assert start_following_active_snapshot(get_settings(), intel.switch, keeper) is None
