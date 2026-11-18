"""With external intelligence OFF the app is exactly what it was: no intelligence collection is created or
written, no snapshot is built, the original writer and prompt version run, nothing intelligence-related
is stored on a plan or a scenario, and the adapter returns before it touches any store. The suite runs
OFF by default (tests/conftest.py), so the app's own tests are the rest of this proof."""

from types import SimpleNamespace
from typing import Any

import pytest

from app.core.config import get_settings
from app.core.constants import Collection, PromptVersion, Queue, TaskName
from app.core.database import get_mongodb
from app.crud import admin as admin_crud
from app.crud import remediation as remediation_crud
from app.crud import scenarios as scenario_crud
from app.crud.admin_jobs import get_admin_job_repository
from app.crud.audit import get_audit_repository
from app.crud.base import get_query_vector_repository
from app.crud.embeddings import get_embedding_repository
from app.crud.indexes import create_all_indexes
from app.crud.intel import get_intel_feed_repository, get_intel_record_repository, get_intel_snapshot_repository
from app.crud.scenarios import get_threat_scenario_repository
from app.domain.intel.switch import IntelligenceSwitch, get_intelligence_switch
from app.worker import intel as worker_intel
from app.worker import lifecycle
from app.worker.celery_app import celery_app
from app.worker.intel import refresh_external_intelligence
from tests.external_intelligence.conftest import Intel
from tests.planner_samples import planned
from tests.test_worker import _worker_starting
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

_INTEL_COLLECTIONS = (Collection.INTEL, Collection.EXTERNAL_FEED_STATUS, Collection.EXTERNAL_INTELLIGENCE_SNAPSHOTS)


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
        assert content["prompt_version"] == PromptVersion.SCENARIO_WRITER
        assert not {"evidence", "evidence_mode", "applicability", "intel_search"} & set(content)
    for threat in _sessions().find_one({"_id": record_id})["plan"]["threats"]:
        assert "evidence" not in threat and "intel_search" not in threat
    assert _no_intel_collection()


def test_the_master_switch_off_decides_the_original_style_before_any_read() -> None:
    """G229: the batch decides its style ONCE, from the switch; with it off the batch is written in the
    original style and never searches (attach_evidence is only ever called for an evidence-story batch)."""
    switch = IntelligenceSwitch(Untouched(), env_enabled=lambda: False)  # type: ignore[arg-type]
    assert switch.is_on() is False and switch.is_on(sure=True) is False


def test_the_runtime_switch_off_writes_the_original_style_and_searches_nothing(intel: Intel, story_chat: Any) -> None:
    """With the runtime switch off, a whole write job reads and searches no intelligence."""
    intel.switch.enabled = False
    assert get_intelligence_switch().is_on() is False
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (scenario,) = _scenarios_of(record_id)
    assert intel.finder.calls == [] and "evidence" not in scenario["content"]


def _only_the_intelligence_indexes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The app's own index makers stand still, so these tests look at the intelligence ones alone."""
    providers = (
        get_audit_repository,
        get_embedding_repository,
        get_query_vector_repository,
        get_admin_job_repository,
        get_threat_scenario_repository,
        remediation_crud.get_remediation_repository,
        scenario_crud.get_threat_scenario_session_repository,
    )
    for provider in providers:
        monkeypatch.setattr(provider(), "create_indexes", lambda: None)
    monkeypatch.setattr(admin_crud, "store", lambda _db: SimpleNamespace(create_indexes=lambda: None))


def test_start_up_makes_no_intelligence_index_or_collection_while_off(monkeypatch: pytest.MonkeyPatch) -> None:
    _only_the_intelligence_indexes(monkeypatch)
    create_all_indexes()
    assert _no_intel_collection()


def test_start_up_makes_the_indexes_and_seeds_the_sources_only_while_on(monkeypatch: pytest.MonkeyPatch) -> None:
    _only_the_intelligence_indexes(monkeypatch)
    done: list[str] = []

    made = {
        "intel_records": (get_intel_record_repository(), "create_indexes"),
        "intel_snapshots": (get_intel_snapshot_repository(), "create_indexes"),
        "intel_feeds": (get_intel_feed_repository(), "create_missing_intel_feeds"),
    }
    for name, (repository, method) in made.items():
        monkeypatch.setattr(repository, method, lambda name=name: done.append(name))
    monkeypatch.setattr(get_settings(), "external_intelligence_enabled", True)
    create_all_indexes()
    assert done == ["intel_records", "intel_snapshots", "intel_feeds"]


def test_no_refresh_is_scheduled_and_a_stray_one_does_nothing_while_off(monkeypatch: pytest.MonkeyPatch) -> None:
    assert TaskName.REFRESH_EXTERNAL_INTELLIGENCE not in celery_app.conf.beat_schedule
    assert TaskName.REFRESH_EXTERNAL_INTELLIGENCE in celery_app.conf.task_routes  # a manual send is still routed
    monkeypatch.setattr(worker_intel.schedule, "get_intel_schedule_repository", Untouched)
    refresh_external_intelligence()  # the switch is off, no store is read (the schedule's neither): returns
    assert _no_intel_collection()


def test_the_worker_warm_up_does_nothing_while_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(worker_intel, "get_evidence_index_keeper", Untouched)
    lifecycle.warm_up_external_intelligence(_worker_starting("threads", Queue.SCENARIOS))
    assert get_intelligence_switch().is_on() is False


def test_a_planned_threat_carries_no_evidence_key_until_it_was_searched() -> None:
    record = planned("lib:1", "Threat 1").to_record({})
    assert "evidence" not in record and "intel_search" not in record
