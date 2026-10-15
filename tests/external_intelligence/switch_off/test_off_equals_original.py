"""With external intelligence OFF the app is exactly what it was: no intelligence collection is created or
written, no snapshot is built, the original writer and prompt version run, nothing intelligence-related
is stored on a plan or a scenario, and the adapter returns before it touches any store. The suite runs
OFF by default (tests/conftest.py), so the app's own tests are the rest of this proof."""

from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import (
    AuditAction,
    Collection,
    TaskName,
    WriterStyle,
)
from app.core.database import get_mongodb
from app.data_access import indexes
from app.engine.scenarios.writing.writing_prompts import WRITER_PROMPT_VERSION
from app.worker import lifecycle
from app.worker.celery_app import celery_app
from app.worker.external_intelligence import intel_access as access_module
from app.worker.external_intelligence.intel_access import IntelAccess, get_intel_access
from app.worker.external_intelligence.refresh_task import refresh_external_intelligence
from tests.external_intelligence.conftest import Intel
from tests.planner_samples import planned
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

_INTEL_COLLECTIONS = (
    Collection.INTEL,
    Collection.EXTERNAL_FEED_STATUS,
    Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS,
)


class Untouched:
    """Anything that reads, writes or searches would call one of these."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"touched {name} while external intelligence is off")


def _no_intel_collection() -> bool:
    return not set(_INTEL_COLLECTIONS) & set(get_mongodb().list_collection_names())


@pytest.fixture(autouse=True)
def start_without_intelligence_collections() -> None:
    """The ON tests (the real stores) leave their collections in the shared test database. Each OFF test
    starts without them, so their absence afterwards proves that the OFF path created none."""
    database = get_mongodb()
    for name in _INTEL_COLLECTIONS:
        database.drop_collection(name)


def test_the_suite_runs_off() -> None:
    assert get_settings().external_intelligence_enabled is False


@pytest.mark.usefixtures("chat", "sent")
def test_a_whole_run_is_written_by_the_original_writer_and_stores_nothing_of_intelligence() -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    assert _deliver_until_done(record_id) == 1
    stored = _scenarios_of(record_id)
    assert len(stored) == 2
    for scenario in stored:
        content = scenario["content"]
        assert content["prompt_version"] == WRITER_PROMPT_VERSION
        assert not {"evidence", "evidence_mode", "applicability", "intel_search"} & set(content)
    for threat in _sessions().find_one({"_id": record_id})["plan"]["threats"]:
        assert "evidence" not in threat and "intel_search" not in threat
    audit = get_mongodb()[Collection.AUDIT]
    assert (
        audit.count_documents(
            {"target.id": record_id, "action": AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED}
        )
        == 0
    )
    assert _no_intel_collection()


def test_the_master_switch_off_decides_the_original_style_before_any_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G229: the batch decides its style ONCE, from the switch; with it off the batch is written in the
    original style and never searches (EvidenceAtWrite is only ever called for an evidence-story batch)."""
    monkeypatch.setattr(access_module, "get_mongodb", lambda: Untouched())
    access = IntelAccess(finder=Untouched, is_stale=Untouched, relevance=Untouched)  # type: ignore[arg-type]
    assert access.writer_style() is WriterStyle.ORIGINAL
    assert access.plan_intel([], None) == ({}, {})  # type: ignore[arg-type]  # nothing read when off


def test_the_runtime_switch_off_writes_the_original_style_and_searches_nothing(
    intel: Intel, story_chat: Any
) -> None:
    """With the runtime switch off, a whole write job reads and searches no intelligence."""
    intel.switch.enabled = False
    assert intel.access.writer_style() is WriterStyle.ORIGINAL
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (scenario,) = _scenarios_of(record_id)
    assert intel.finder.calls == [] and "evidence" not in scenario["content"]


def test_no_runtime_installed_counts_as_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    assert IntelAccess().is_on() is False


class Quiet:
    """Stands in for the app's own index makers, so these tests look at the intelligence ones alone."""

    def __init__(self, *_: object) -> None: ...

    def __getattr__(self, name: str) -> Any:
        return lambda *args, **kwargs: None


def _only_the_intelligence_indexes(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "ApiClientRepository",
        "SessionRepository",
        "ScenarioRepository",
        "RemediationRepository",
        "AiCallRecords",
        "LibraryVectors",
        "QueryVectors",
        "AdminJobRecords",
    ):
        monkeypatch.setattr(indexes, name, Quiet)
    monkeypatch.setattr(indexes, "ensure_audit_indexes", lambda: None)


def test_start_up_makes_no_intelligence_index_or_collection_while_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_the_intelligence_indexes(monkeypatch)
    indexes.ensure_indexes()
    assert _no_intel_collection()


def test_start_up_makes_the_indexes_and_seeds_the_sources_only_while_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _only_the_intelligence_indexes(monkeypatch)
    done: list[str] = []

    def recorder(name: str) -> type:
        class Store:
            def __init__(self, db: object) -> None: ...

            def ensure_indexes(self) -> None:
                done.append(name)

            def seed_sources(self) -> None:
                done.append(name)

        return Store

    for attribute in ("IntelRecordStore", "SnapshotPointerStore", "FeedStatusStore"):
        monkeypatch.setattr(indexes, attribute, recorder(attribute))
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    indexes.ensure_indexes()
    assert done == ["IntelRecordStore", "SnapshotPointerStore", "FeedStatusStore"]


def test_no_refresh_is_scheduled_and_a_stray_one_does_nothing_while_off() -> None:
    assert TaskName.REFRESH_EXTERNAL_INTELLIGENCE not in celery_app.conf.beat_schedule
    assert (
        TaskName.REFRESH_EXTERNAL_INTELLIGENCE in celery_app.conf.task_routes
    )  # a manual send is still routed
    refresh_external_intelligence()  # no runtime, no store: returns


def test_the_worker_warm_up_does_nothing_while_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.worker.external_intelligence.warm_up.get_evidence_index_keeper", Untouched)
    lifecycle.warm_up_external_intelligence()
    assert get_intel_access().writer_style() is WriterStyle.ORIGINAL


def test_a_planned_threat_carries_no_evidence_key_until_it_was_searched() -> None:
    record = planned("lib:1", "Threat 1").to_record()
    assert "evidence" not in record and "intel_search" not in record


def test_a_switch_that_cannot_be_read_counts_as_off(intel: Intel) -> None:
    def broken() -> bool:
        raise OSError("the store is down")

    intel.switch.is_enabled = broken  # type: ignore[method-assign]
    assert intel.access.is_on() is False and intel.access.writer_style() is WriterStyle.ORIGINAL
