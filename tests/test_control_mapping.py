"""Controls for written scenarios (Step 13, BUILD_PLAN S31-S34): T-CTL-01..10, with fake AI models."""

import dataclasses
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from pymongo.errors import DuplicateKeyError

from app.ai import reranks_in_background
from app.core.asset_types import asset_type_fits, unknown_asset_type
from app.core.config import get_settings
from app.core.constants import (
    Collection,
    ControlMatch,
    ControlMessage,
    Controls,
    ErrorCode,
    RunKind,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import ControlsNotMapped, Unavailable
from app.data_access.scenario.repository import (
    ControlsDeliveryRepository,
    ScenarioRepository,
    TitleTaken,
    controls_deliveries,
    scenario_controls,
    scenarios,
    session_status_from_record,
)
from app.domain.scenario.controls import ControlMapper
from app.domain.scenario.library_rules import compatible_asset_types, place_asset_types
from app.models.library import LibraryControl, ThreatLibrary
from app.search.service import LibrarySearch
from app.worker.tasks import controls as controls_job
from tests.fakes import FakeEmbeddings
from tests.planner_samples import CONTEXT

_BOTH = {"IT", "OT", r"IT\OT"}


@pytest.mark.parametrize(
    ("asset_type", "system_types", "allowed"),
    [
        ("OT", ["OT", "IT"], _BOTH),  # an OT asset's scenario on its IT system: both
        ("OT", ["OT"], {"OT", r"IT\OT"}),
        (" ot ", [], {"OT", r"IT\OT"}),  # labels as stored: any case, any spacing
        (None, ["IT"], {"IT", r"IT\OT"}),
        ("Physical", [None, ""], set()),  # nothing recognised: only untyped controls fit, never every control
        ("IT-OT", [], set()),  # not a value: never read as both
    ],
)
def test_the_pool_follows_the_asset_and_the_scenarios_own_systems(
    asset_type: str | None, system_types: list[str | None], allowed: set[str]
) -> None:
    """T-CTL-02 (S31): spec v4.0 §7.5.2, the pool is never silently widened."""
    assert compatible_asset_types(asset_type, system_types) == allowed


def test_the_control_search_ranks_only_compatible_controls_before_the_cut() -> None:
    """T-CTL-02 (S31): an IT control that matches best never takes an OT scenario's place; a control with no
    AssetType always takes part."""
    controls = (
        LibraryControl(1, "C-IT", "IT", None, "Offline backup", "Keep an offline backup copy of servers"),
        LibraryControl(2, "C-OT", "OT", None, "Backup of controller logic", None),
        LibraryControl(3, "C-ANY", None, None, "Backup policy", None),
    )
    stamp = (("Control_Library", b""),)  # as the library cache stamps every loaded version
    library = SimpleNamespace(threat_library=ThreatLibrary((), ()), control_library=controls, stamp=stamp)
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), FakeEmbeddings())  # type: ignore[arg-type]
    snapshot = search.snapshot()
    (best,) = snapshot.find_controls(["offline backup copy"], top_k=1)
    assert best[0][0].code == "C-IT"
    (ot_only,) = snapshot.find_controls(["offline backup copy"], 3, allowed_types={"OT", r"IT\OT"})
    assert {control.code for control, _ in ot_only} == {"C-OT", "C-ANY"}
    (untyped_only,) = snapshot.find_controls(["offline backup copy"], 3, allowed_types=frozenset())
    assert {control.code for control, _ in untyped_only} == {"C-ANY"}


@pytest.mark.parametrize("both", [r"IT\OT", r"it\ot", r" IT \ OT "])
def test_an_asset_recorded_as_both_gets_both_kinds_of_control(both: str) -> None:
    r"""IT\OT means both, any case or spacing ("IT-OT" is not a value)."""
    assert compatible_asset_types(both, []) == _BOTH


@pytest.mark.parametrize(
    ("asset_type", "fits"), [("OT", False), ("IT", True), (r"IT\OT", True), (None, True), ("IT-OT", True)]
)
def test_a_control_or_threat_fits_by_its_own_asset_type(asset_type: str | None, fits: bool) -> None:
    """On an IT system, an OT row never fits; an IT or both row does; an empty one, or one whose value
    is not a type ("IT-OT", noted for a curator), fits everywhere rather than being silently dropped."""
    assert asset_type_fits(asset_type, compatible_asset_types("IT", [])) is fits
    assert unknown_asset_type(asset_type) is (asset_type == "IT-OT")


class _Clashing:
    """A collection whose server names no index in its duplicate-key error (an older or compatible one)."""

    def __init__(self, written: int) -> None:
        self.written = written

    def replace_one(self, *_: object, **__: object) -> None:
        raise DuplicateKeyError("E11000 duplicate key", details={})

    def count_documents(self, *_: object, **__: object) -> int:
        return self.written


@pytest.mark.parametrize(("written", "title_taken"), [(0, True), (1, False)])
def test_an_unnamed_duplicate_key_is_checked_never_taken_as_written(written: int, title_taken: bool) -> None:
    """Review fix 7: before, it was always "already written": the path was served with its failure card."""
    clashing = ScenarioRepository(_Clashing(written))  # type: ignore[arg-type]
    if title_taken:
        with pytest.raises(TitleTaken):
            clashing.save_scenario({"_id": "s1"})
    else:
        assert clashing.save_scenario({"_id": "s1"}) is False


#: As the run freezes it (domain/scenario/plan.py): the asset's IT/OT code is `asset.category_code`;
#: `asset_context.asset_type` is the platform's free-text type.
_OT_CONTEXT = dataclasses.replace(
    CONTEXT,
    asset=CONTEXT.asset | {"type": "Control system", "category_code": "OT"},
    asset_context=CONTEXT.asset_context | {"asset_type": "Control system"},
    systems=[CONTEXT.systems[0] | {"category_code": "OT"}, CONTEXT.systems[1] | {"category_code": "IT"}],
)
_SCENARIO = {
    "content": {
        "title": "Loss of backup integrity",
        "statement": "A ransomware gang could encrypt the backup of the SCADA server.",
        "risk_statement": "Loss of recoverable backups at Grid Control Centre could stop transmission.",
        "category": "Tampering",
        "threat": {"type": "Malware", "name": "Ransomware encrypts backup servers"},
        "actors": [{"name": "Ransomware gang", "role": "acting"}, {"name": "Insider", "role": "alternate"}],
        "systems": [{"id": 321, "name": "SCADA server", "entry_point": True}],
    }
}


class _ScoresByText:
    """A reranker scoring each control by its name (0-100), recording what it was asked."""

    def __init__(self, scores: dict[str, float]) -> None:
        self.scores = scores
        self.asked: list[tuple[str, list[str]]] = []
        self.in_background: list[bool] = []  # G222: was each call marked background work?

    def score_relevance(self, query: str, documents: list[str]) -> list[float]:
        self.asked.append((query, documents))
        self.in_background.append(reranks_in_background())
        return [self.scores.get(document.split(":")[0], 0.0) for document in documents]


def _snapshot(*controls: LibraryControl) -> Any:
    stamp = (("Control_Library", b""),)  # as the library cache stamps every loaded version
    library = SimpleNamespace(threat_library=ThreatLibrary((), ()), control_library=controls, stamp=stamp)
    search = LibrarySearch(SimpleNamespace(get_loaded_libraries=lambda: library), FakeEmbeddings())  # type: ignore[arg-type]
    return search.snapshot()


_CONTROLS = (
    LibraryControl(1, "C-IT", "IT", "BCDR", "Offline backup", "Keep an offline backup copy"),
    LibraryControl(2, "C-OT", "OT", "BCDR", "Backup of controller logic", "Back up PLC and SCADA logic"),
    LibraryControl(3, "C-ANY", None, "BCDR", "Backup policy", "A written backup policy"),
)


def test_controls_come_from_the_scenario_and_risk_and_only_compatible_ones_are_kept() -> None:
    """T-CTL-01/02/03 (S32): the query holds both statements; an OT scenario on its OT system gets no IT
    control; every control at or above the cut-off is kept, best first, ranks 1..n."""
    rerank = _ScoresByText(
        {"Offline backup": 95.0, "Backup of controller logic": 87.0, "Backup policy": 70.0}
    )
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [(item.code, item.rank, item.match) for item in mapping.items] == [
        ("C-OT", 1, ControlMatch.EXACT),
        ("C-ANY", 2, ControlMatch.EXACT),
    ]
    # Kept with the mapping: the results show it without reading the library.
    assert mapping.items[0].to_record()["description"] == "Back up PLC and SCADA logic"
    query = rerank.asked[0][0]
    content = _SCENARIO["content"]
    assert content["statement"] in query and content["risk_statement"] in query
    assert "Attacker: Ransomware gang" in query and mapping.warning is None and mapping.query == query


def test_a_scenarios_controls_follow_its_own_place_not_the_whole_asset() -> None:
    """As for its threat: a scenario on the IT system of an OT asset gets IT controls only, however well an
    OT one scores; a scenario on the asset itself gets the asset's type (its code, never its free-text type
    "Control system")."""
    rerank = _ScoresByText({"Backup of controller logic": 90.0, "Offline backup": 80.0})
    on_historian = {"content": _SCENARIO["content"] | {"systems": [{"id": 322, "name": "Historian"}]}}
    mapping = ControlMapper(rerank).map_controls(on_historian, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [item.code for item in mapping.items] == ["C-IT"]
    on_asset = {"content": _SCENARIO["content"] | {"systems": []}}
    mapping = ControlMapper(rerank).map_controls(on_asset, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [item.code for item in mapping.items] == ["C-OT"]


def test_each_system_whose_type_is_not_recorded_takes_the_assets_among_recorded_ones() -> None:
    """An unrecorded system among recorded ones takes the asset's type, so an OT asset's scenario on an
    unrecorded and an IT system keeps the OT controls."""
    assert place_asset_types("OT", [None, "IT"]) == _BOTH
    assert place_asset_types("OT", []) == {"OT", r"IT\OT"}  # the asset itself


def test_a_system_whose_type_is_not_recorded_takes_the_assets() -> None:
    """Unknown is not a type: a scenario on a system with no recorded category code gets the asset's type,
    never "untyped controls only" (which would leave it no control at all)."""
    untyped_system = dataclasses.replace(
        _OT_CONTEXT, systems=[_OT_CONTEXT.systems[0] | {"category_code": None}, _OT_CONTEXT.systems[1]]
    )
    rerank = _ScoresByText({"Backup of controller logic": 90.0, "Offline backup": 80.0})
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, untyped_system, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [item.code for item in mapping.items] == ["C-OT"]


def test_none_at_the_cut_off_keeps_the_single_nearest_with_a_warning() -> None:
    """T-CTL-04 (S32): never empty while a compatible control exists; the reviewer is told it is nearest."""
    rerank = _ScoresByText({"Backup of controller logic": 41.0, "Backup policy": 22.0})
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    nearest = [(item.code, item.match, item.score) for item in mapping.items]
    assert nearest == [("C-OT", ControlMatch.NEAREST, 41.0)] and mapping.warning and "60" in mapping.warning


def test_the_control_threshold_is_the_owners_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    """CONTROL_SIMILARITY_THRESHOLD decides "exact"; 87 and 70 both pass the default 60, neither passes
    88 (the nearest alone is kept, the warning naming 88)."""
    rerank = _ScoresByText({"Backup of controller logic": 87.0, "Backup policy": 70.0})
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [item.match for item in mapping.items] == [ControlMatch.EXACT, ControlMatch.EXACT]
    monkeypatch.setattr(get_settings(), "control_similarity_threshold", 88.0)
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert [(item.code, item.match) for item in mapping.items] == [("C-OT", ControlMatch.NEAREST)]
    assert mapping.warning and "88" in mapping.warning


def test_an_it_and_an_ot_twin_are_one_control_and_the_higher_score_stays() -> None:
    """T-CTL-05 (S32): the same text under two ids (an IT and an OT copy) is mapped once."""
    twins = (
        LibraryControl(7, "OT-7", "OT", None, "Network segmentation", "Separate zones"),
        LibraryControl(8, "IT-8", "IT", None, "Network segmentation", "Separate zones"),
    )
    on_both = dataclasses.replace(_OT_CONTEXT, asset=_OT_CONTEXT.asset | {"category_code": r"IT\OT"})
    on_asset = {"content": _SCENARIO["content"] | {"systems": []}}  # an IT\OT asset: both twins compete
    rerank = _ScoresByText({"Network segmentation": 80.0})
    mapping = ControlMapper(rerank).map_controls(on_asset, on_both, _snapshot(*twins))  # type: ignore[arg-type]
    assert len(rerank.asked[0][1]) == 2
    assert [item.control_id for item in mapping.items] == [7]


def test_an_empty_library_fails_and_no_control_of_the_type_keeps_the_nearest_of_another() -> None:
    """control_library_empty only when
    the library is empty; with no control of the scenario's type, the nearest of another type is kept
    (MIN_CONTROLS at most, never a strong set of another type), and the warning says so."""
    with pytest.raises(ControlsNotMapped) as empty:
        ControlMapper(_ScoresByText({})).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot())  # type: ignore[arg-type]
    assert empty.value.code == ErrorCode.CONTROL_LIBRARY_EMPTY
    it_only = _snapshot(
        LibraryControl(1, "C-IT", "IT", None, "Offline backup", None),
        LibraryControl(2, "C-IT-2", "IT", None, "Email filtering", None),
    )
    rerank = _ScoresByText({"Offline backup": 90.0, "Email filtering": 85.0})
    mapping = ControlMapper(rerank).map_controls(_SCENARIO, _OT_CONTEXT, it_only)  # type: ignore[arg-type]
    assert mapping.items[0].control_id == 1 and len(mapping.items) == get_settings().min_controls
    expected = ControlMessage.OTHER_TYPE.format(types=r"IT\OT, OT")
    assert mapping.warning == expected and mapping.left_out == 0


def test_a_reranker_outage_is_raised_and_a_long_query_is_cut() -> None:
    """T-CTL-10 (S32): the job retries an outage; the query never passes Controls.QUERY_MAX_CHARS."""

    class _Down(_ScoresByText):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            raise Unavailable("rerank down")

    with pytest.raises(Unavailable):
        ControlMapper(_Down({})).map_controls(_SCENARIO, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    long = {"content": _SCENARIO["content"] | {"statement": "backup " * 2_000}}
    rerank = _ScoresByText({"Backup policy": 70.0})
    mapping = ControlMapper(rerank).map_controls(long, _OT_CONTEXT, _snapshot(*_CONTROLS))  # type: ignore[arg-type]
    assert len(mapping.query) <= 4_000 and mapping.query.startswith("Category: Tampering")


def _waiting_scenario(**controls: Any) -> tuple[str, str]:
    """A written scenario of a finished run whose controls wait; (run id, scenario id)."""
    session_id, scenario_id = f"run-{uuid.uuid4().hex}", uuid.uuid4().hex
    get_mongodb()[Collection.SESSIONS].insert_one({"_id": session_id, "entity_id": 86, "status": Status.DONE})
    get_mongodb()[Collection.SCENARIOS].insert_one(
        {
            "_id": scenario_id,
            "session_id": session_id,
            "path_id": "p1",
            "status": ScenarioStatus.DONE,
            "superseded_by": None,
            "decision": "pending",
            "content": {"title": "t"},
            "created_at": datetime.now(UTC),
            "controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": datetime.now(UTC)} | controls,
        }
    )
    return session_id, scenario_id


def _controls_of(scenario_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id})["controls"]


def test_one_scenario_is_claimed_by_one_worker_and_a_stale_worker_cannot_finish() -> None:
    """T-CTL-06 (S33): one conditional update per claim; every later write fenced on the claim's task id."""
    leases = scenario_controls
    session_id, scenario_id = _waiting_scenario()
    first = leases.claim_scenario_controls(session_id, "worker-a")
    assert first is not None and first["_id"] == scenario_id and first["controls"]["attempts"] == 1
    assert leases.claim_scenario_controls(session_id, "worker-b") is None
    expired = {"controls.lease_until": datetime.now(UTC) - timedelta(seconds=1)}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": expired})
    assert leases.claim_scenario_controls(session_id, "worker-b") is not None  # worker-a died: lease ran out
    assert not leases.update_scenario_controls(scenario_id, "worker-a", 1, Status.DONE, mapping={"items": []})
    mapping = {"items": [{"control_id": 1}], "warning": None}
    assert leases.update_scenario_controls(scenario_id, "worker-b", 2, Status.DONE, mapping=mapping)
    assert (_controls_of(scenario_id)["status"], _controls_of(scenario_id)["attempts"]) == (Status.DONE, 2)


def test_a_redelivered_copy_with_the_same_task_id_shuts_the_hung_copy_out() -> None:
    """Celery reuses the task id on a redelivery: a hung copy and the copy that claimed again after its lease
    ran out share it, so only the attempts the newer claim counted let a write through."""
    leases = scenario_controls
    session_id, scenario_id = _waiting_scenario()
    hung = leases.claim_scenario_controls(session_id, "task-1")
    expired = {"controls.lease_until": datetime.now(UTC) - timedelta(seconds=1)}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": expired})
    again = leases.claim_scenario_controls(session_id, "task-1")
    assert hung is not None and again is not None
    stale, fresh = hung["controls"]["attempts"], again["controls"]["attempts"]
    assert not leases.update_scenario_controls(scenario_id, "task-1", stale, Status.RUNNING)
    late = {"code": "x", "message": "late"}
    assert not leases.update_scenario_controls(scenario_id, "task-1", stale, Status.FAILED, error=late)
    mapping = {"items": [{"control_id": 1}], "warning": None}
    assert leases.update_scenario_controls(scenario_id, "task-1", fresh, Status.DONE, mapping=mapping)
    assert _controls_of(scenario_id)["status"] == Status.DONE


def test_an_outage_queues_the_mapping_again_until_its_last_attempt_fails_it() -> None:
    """T-CTL-07 (S33)."""
    leases = scenario_controls
    error = {"code": "unavailable", "message": "busy"}
    session_id, scenario_id = _waiting_scenario()
    leases.claim_scenario_controls(session_id, "w")
    assert leases.update_scenario_controls(scenario_id, "w", 1, Status.QUEUED, error=error)
    assert _controls_of(scenario_id)["status"] == Status.QUEUED
    last = {"controls.attempts": Controls.MAX_ATTEMPTS - 1}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": last})
    leases.claim_scenario_controls(session_id, "w")
    assert leases.update_scenario_controls(
        scenario_id, "w", Controls.MAX_ATTEMPTS, Status.QUEUED, error=error
    )
    assert (
        _controls_of(scenario_id)["status"] == Status.FAILED and _controls_of(scenario_id)["error"] == error
    )


def test_the_sweep_never_maps_a_hand_written_scenario() -> None:
    """Rule R1T (S55): its controls are mapped only inside its plan request; a failed top-up stays failed."""
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    run_id, scenario_id = _waiting_scenario(status=Status.FAILED, last_attempt_at=long_ago, attempts=1)
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": scenario_id}, {"$set": {"source": RunKind.MANUAL}})
    assert run_id not in scenario_controls.requeue_stalled_controls()
    assert _controls_of(scenario_id)["status"] == Status.FAILED


def test_the_sweep_requeues_lost_dead_and_long_failed_mappings_only() -> None:
    """T-CTL-07 (S33): the queued one whose message was lost, the running one whose worker died, the one that
    failed over 30 minutes ago; never a recent failure or a fresh queue entry."""
    now = datetime.now(UTC)
    lost = _waiting_scenario(queued_at=now - timedelta(seconds=Controls.RESEND_QUEUED_AFTER_SECONDS + 5))
    dead = _waiting_scenario(status=Status.RUNNING, lease_until=now - timedelta(seconds=1))
    attempts_left = Controls.MAX_ATTEMPTS - 1
    old_failure = _waiting_scenario(
        status=Status.FAILED, last_attempt_at=now - timedelta(hours=1), attempts=attempts_left
    )
    recent_failure = _waiting_scenario(status=Status.FAILED, last_attempt_at=now, attempts=1)
    fresh = _waiting_scenario()
    touched = scenario_controls.requeue_stalled_controls()
    assert {lost[0], dead[0], old_failure[0]} <= set(touched)
    assert not {recent_failure[0], fresh[0]} & set(touched)
    assert (
        _controls_of(old_failure[1])["status"] == Status.QUEUED
        and _controls_of(old_failure[1])["attempts"] == attempts_left
    )
    assert _controls_of(recent_failure[1])["status"] == Status.FAILED


def test_the_sweep_never_requeues_a_failure_that_used_its_last_attempt() -> None:
    """A mapping failed Controls.MAX_ATTEMPTS times stays failed: the sweep never retries it forever."""
    long_ago = datetime.now(UTC) - timedelta(hours=1)
    run_id, scenario_id = _waiting_scenario(
        status=Status.FAILED, last_attempt_at=long_ago, attempts=Controls.MAX_ATTEMPTS
    )
    assert run_id not in scenario_controls.requeue_stalled_controls()
    assert _controls_of(scenario_id)["status"] == Status.FAILED


def test_a_mapping_that_keeps_stopping_its_worker_is_given_up_after_its_last_attempt() -> None:
    """Its lease expired on its last attempt: never claimed again, and the sweep fails it (job_abandoned)
    instead of queueing it for ever."""
    expired = datetime.now(UTC) - timedelta(seconds=1)
    run_id, scenario_id = _waiting_scenario(
        status=Status.RUNNING, lease_until=expired, attempts=Controls.MAX_ATTEMPTS
    )
    assert scenario_controls.claim_scenario_controls(run_id, "w") is None
    assert scenario_controls.claim_scenario_controls_by_id(scenario_id, "w:plan") is None
    assert run_id not in scenario_controls.requeue_stalled_controls()
    controls = _controls_of(scenario_id)
    assert (controls["status"], controls["error"]["code"]) == (Status.FAILED, ErrorCode.JOB_ABANDONED)
    assert get_mongodb()[Collection.SESSIONS].find_one({"_id": run_id})["counts"]["controls_failed"] == 1


def test_an_older_count_never_overwrites_a_newer_one() -> None:
    """T-CTL-07 (S33, BLUEPRINT Rule S12): two jobs refresh one run's counts; the later computation wins."""
    sessions = get_mongodb()[Collection.SESSIONS]
    session_id, _ = _waiting_scenario()
    sessions.update_one({"_id": session_id}, {"$set": {"counts": {"written": 0}}})
    assert scenarios.update_scenario_session_counts(session_id)["controls_waiting"] == 1
    assert sessions.find_one({"_id": session_id})["counts"]["controls_waiting"] == 1
    newer = datetime.now(UTC) + timedelta(minutes=1)
    sessions.update_one({"_id": session_id}, {"$set": {"counts.written": 99, "counts_at": newer}})
    scenarios.update_scenario_session_counts(session_id)
    assert sessions.find_one({"_id": session_id})["counts"]["written"] == 99


@pytest.fixture
def mapping_run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """A finished run of the OT asset with two written scenarios waiting for controls; its models faked."""
    record_id = f"run-{uuid.uuid4().hex}"
    get_mongodb()[Collection.SESSIONS].insert_one(
        {"_id": record_id, "entity_id": 86, "asset_id": 1, "status": Status.DONE, "step": "scenarios",
         "context": _OT_CONTEXT.to_record(), "counts": {}, "updated_at": datetime.now(UTC)}
    )  # fmt: skip
    for number in (1, 2):
        get_mongodb()[Collection.SCENARIOS].insert_one(
            {"_id": f"{record_id}-{number}", "session_id": record_id, "path_id": f"p{number}",
             "status": ScenarioStatus.DONE, "superseded_by": None, "decision": "pending",
             "content": _SCENARIO["content"], "created_at": datetime.now(UTC),
             "controls": {"status": Status.QUEUED, "attempts": 0, "queued_at": datetime.now(UTC)}}
        )  # fmt: skip
    state: dict[str, Any] = {"record_id": record_id, "published": [], "sent": []}
    state["rerank"] = _ScoresByText({"Backup of controller logic": 87.0, "Backup policy": 70.0})
    library = SimpleNamespace(snapshot=lambda: _snapshot(*_CONTROLS))
    monkeypatch.setattr(controls_job, "get_library_search", lambda: library)
    monkeypatch.setattr(controls_job, "get_rerank_model", lambda: state["rerank"])
    monkeypatch.setattr(controls_job, "publish_session_status", state["published"].append)
    monkeypatch.setattr(controls_job, "send_job", lambda *args: state["sent"].append(args))
    return state


def _deliver(record_id: str, task_id: str) -> int | None:
    """One tsg_map_controls delivery as the task makes it: the run's delivery lease first, then its turn. None
    when another delivery holds the run (the message ends at once)."""
    context = controls_deliveries.claim_controls_delivery(record_id, task_id)
    if context is None:
        return None
    return controls_job.RunControls(record_id, task_id, context).map_all()


def test_the_control_mapping_job_reranks_as_background_work(mapping_run: dict[str, Any]) -> None:
    """G222: on the laptop's CPU reranker a waiting scenario goes before the mapping job's reranks."""
    assert _deliver(mapping_run["record_id"], "task-1") == 2
    assert mapping_run["rerank"].in_background == [True, True]


def _run_record(record_id: str) -> dict[str, Any]:
    return get_mongodb()[Collection.SESSIONS].find_one({"_id": record_id})


def test_every_written_scenario_gets_its_controls_and_the_run_stops_waiting(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-CTL-06 (S34): one at a time, each saved with what made it; counts and watchers after each; the run's
    step reads `controls` only while controls wait; a repeated message maps nothing twice."""
    record_id = mapping_run["record_id"]
    waiting = _run_record(record_id) | {"counts": {"controls_waiting": 2}}
    assert session_status_from_record(waiting).step == "controls"
    mapping = controls_job.RunControls._map_one
    monkeypatch.setattr(  # each mapping takes 20 ms at least: the status adds up its controls time
        controls_job.RunControls,
        "_map_one",
        lambda self, scenario: (time.sleep(0.02), mapping(self, scenario))[1],
    )
    assert _deliver(record_id, "task-1") == 2
    mapped = _controls_of(f"{record_id}-1")
    assert mapped["status"] == Status.DONE and [item["code"] for item in mapped["items"]] == ["C-OT", "C-ANY"]
    # G200: the threshold "exact" meant for this mapping is kept with it.
    assert set(mapped["made_with"]) == {
        "rerank_model", "embedding_model", "library", "threshold",
        "candidates", "min_controls", "max_controls", "query_shortened", "mitigations", "ai_controls",
    }  # fmt: skip
    assert mapped["made_with"]["mitigations"] == []  # G234: written without intelligence, none guided it
    assert mapped["made_with"]["threshold"] == 60.0 and mapped["query"]
    assert _run_record(record_id)["counts"]["controls_waiting"] == 0
    assert _run_record(record_id)["timings"]["controls_s"] >= 0.04  # the two mappings, added up
    assert mapping_run["published"] == [record_id] * 2
    assert session_status_from_record(_run_record(record_id)).step == "scenarios"
    assert _deliver(record_id, "task-2") == 0


def test_an_outage_gives_the_scenario_back_and_no_control_of_the_type_still_maps_the_nearest(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-CTL-07/09 (S34): an outage queues the scenario again and is raised (the message retries); a scenario
    with no control of its type gets the nearest of another type, flagged (owner 2026-10-15), never none."""
    record_id = mapping_run["record_id"]

    class _Down(_ScoresByText):
        def score_relevance(self, query: str, documents: list[str]) -> list[float]:
            raise Unavailable("rerank down")

    mapping_run["rerank"] = _Down({})
    with pytest.raises(Unavailable):
        _deliver(record_id, "task-1")
    first = _controls_of(f"{record_id}-1")
    assert (first["status"], first["attempts"], first["error"]["code"]) == (
        Status.QUEUED,
        1,
        ErrorCode.UNAVAILABLE,
    )
    mapping_run["rerank"] = _ScoresByText({"Backup policy": 70.0})
    it_only = SimpleNamespace(
        snapshot=lambda: _snapshot(LibraryControl(1, "C-IT", "IT", None, "Offline backup", None))
    )
    monkeypatch.setattr(controls_job, "get_library_search", lambda: it_only)
    # The message's retry keeps its task id, so it takes back the run it still holds (review 2026-10-11).
    assert _deliver(record_id, "task-1") == 2
    for number in (1, 2):
        controls = _controls_of(f"{record_id}-{number}")
        assert (controls["status"], [item["code"] for item in controls["items"]]) == (Status.DONE, ["C-IT"])
        assert controls["warning"].startswith("No control of asset type(s) ")


def test_the_sweep_sends_one_message_per_run_it_requeued(mapping_run: dict[str, Any]) -> None:
    """T-CTL-07 (S34): tsg_retry_controls, on beat every Controls.SWEEP_EVERY_SECONDS."""
    record_id = mapping_run["record_id"]
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    get_mongodb()[Collection.SCENARIOS].update_many(
        {"session_id": record_id}, {"$set": {"controls.queued_at": long_ago}}
    )
    controls_job.retry_controls()
    assert mapping_run["sent"].count((TaskName.MAP_CONTROLS, record_id, 0)) == 1


def test_an_accepted_version_a_regenerate_replaced_still_gets_its_controls(
    mapping_run: dict[str, Any],
) -> None:
    """G139 (S41 review): a regenerate may replace an accepted version while its controls still wait; the
    reviewer still works with it, so it is mapped (and counted as waiting until then). A replaced pending
    version is not: nobody is shown it."""
    record_id = mapping_run["record_id"]
    scenario_collection = get_mongodb()[Collection.SCENARIOS]
    scenario_collection.update_one(
        {"_id": f"{record_id}-1"}, {"$set": {"superseded_by": "v2", "decision": "accepted"}}
    )
    # G148: a replaced rejected version is not mapped either (nobody works with it).
    scenario_collection.update_one(
        {"_id": f"{record_id}-2"}, {"$set": {"superseded_by": "v2b", "decision": "rejected"}}
    )
    assert scenarios.update_scenario_session_counts(record_id)["controls_waiting"] == 1
    assert _deliver(record_id, "task-1") == 1
    assert _controls_of(f"{record_id}-1")["status"] == Status.DONE
    assert _controls_of(f"{record_id}-2")["status"] == Status.QUEUED
    assert scenarios.update_scenario_session_counts(record_id)["controls_waiting"] == 0


def test_a_delivery_maps_its_turn_then_hands_the_run_to_its_next_message(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G195 (live test 2026-10-11): a delivery maps at most Controls.PER_DELIVERY, then hands the run over and
    queues its next turn; one that finds none waiting releases the run and sends nothing. Two old runs'
    deliveries mapped until none waited and held every worker thread while a new run's writing waited."""
    record_id, message = mapping_run["record_id"], (TaskName.MAP_CONTROLS, mapping_run["record_id"], 0)
    monkeypatch.setattr(Controls, "PER_DELIVERY", 1)
    assert [_deliver(record_id, f"task-{turn}") for turn in range(3)] == [1, 1, 0]
    assert mapping_run["sent"] == [message, message]
    assert "controls_delivery" not in _run_record(record_id)  # released: the next written batch takes it


def test_of_ten_messages_for_one_run_delivered_at_once_exactly_one_maps(mapping_run: dict[str, Any]) -> None:
    """G195: the run's delivery lease is taken in ONE conditional update. On 2026-10-11 ten messages
    redelivered in the same millisecond all passed a look-then-claim check and held every worker thread."""
    record_id = mapping_run["record_id"]
    barrier, taken = threading.Barrier(10), []

    def take(task_id: str) -> None:
        barrier.wait(timeout=10)
        taken.append(controls_deliveries.claim_controls_delivery(record_id, task_id) is not None)

    threads = [threading.Thread(target=take, args=(f"task-{number}",)) for number in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(taken) == [False] * 9 + [True]


def test_a_message_that_finds_the_run_held_ends_at_once_and_its_retry_takes_its_own_lease_back(
    mapping_run: dict[str, Any],
) -> None:
    """G195: another delivery's live lease ends the message (nothing mapped, nothing sent); the holder's own
    retried message (same task id) takes it back; an expired lease is anyone's."""
    record_id, deliveries = mapping_run["record_id"], controls_deliveries
    assert deliveries.claim_controls_delivery(record_id, "holder") is not None
    assert _deliver(record_id, "duplicate") is None
    assert _controls_of(f"{record_id}-1")["status"] == Status.QUEUED and mapping_run["sent"] == []
    assert deliveries.claim_controls_delivery(record_id, "holder") is not None
    expired = {"controls_delivery.until": datetime.now(UTC) - timedelta(seconds=1)}
    get_mongodb()[Collection.SESSIONS].update_one({"_id": record_id}, {"$set": expired})
    assert deliveries.claim_controls_delivery(record_id, "next") is not None


def test_the_sweep_sends_nothing_for_a_run_whose_next_turn_is_on_its_way(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G195: while a run's next-turn message waits in the queue, the sweep sends no second one (a message per
    sweep piled up before); once that hand-over ran out (the message was lost), it sends one."""
    record_id, message = mapping_run["record_id"], (TaskName.MAP_CONTROLS, mapping_run["record_id"], 0)
    monkeypatch.setattr(Controls, "PER_DELIVERY", 1)
    assert _deliver(record_id, "task-1") == 1 and mapping_run["sent"] == [message]
    long_ago = datetime.now(UTC) - timedelta(hours=2)
    scenarios, sessions = get_mongodb()[Collection.SCENARIOS], get_mongodb()[Collection.SESSIONS]
    scenarios.update_one({"_id": f"{record_id}-2"}, {"$set": {"controls.queued_at": long_ago}})
    controls_job.retry_controls()
    assert mapping_run["sent"] == [message]
    scenarios.update_one({"_id": f"{record_id}-2"}, {"$set": {"controls.queued_at": long_ago}})
    sessions.update_one({"_id": record_id}, {"$set": {"controls_delivery.until": long_ago}})
    controls_job.retry_controls()
    assert mapping_run["sent"] == [message, message]


def test_a_scenario_written_while_the_delivery_ended_gets_its_own_message(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G195: a scenario saved after the delivery's last claim found none, whose own message then found the run
    still held and ended, is not left to the sweep's 10 minutes: the delivery sends it one on release."""
    record_id, scenarios = mapping_run["record_id"], get_mongodb()[Collection.SCENARIOS]
    scenarios.update_one({"_id": f"{record_id}-2"}, {"$set": {"controls.status": Status.DONE}})
    release = ControlsDeliveryRepository.release_controls_delivery

    def release_after_a_write(self: ControlsDeliveryRepository, session_id: str, task_id: str) -> None:
        scenarios.update_one({"_id": f"{record_id}-2"}, {"$set": {"controls.status": Status.QUEUED}})
        release(self, session_id, task_id)

    monkeypatch.setattr(ControlsDeliveryRepository, "release_controls_delivery", release_after_a_write)
    assert _deliver(record_id, "task-1") == 1
    assert mapping_run["sent"] == [(TaskName.MAP_CONTROLS, record_id, 0)]


def test_the_task_takes_the_run_then_maps_and_a_store_outage_at_the_take_retries(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G195 (review 2026-10-11): the task itself, not a copy of its body: it takes the run and maps; a run
    another delivery holds ends it at once; an outage while taking the run retries the message (before, it was
    outside the retry and the scenarios waited for the sweep)."""
    record_id = mapping_run["record_id"]
    assert controls_job.map_controls.apply(args=(record_id, 0), task_id="task-1").successful()
    assert _controls_of(f"{record_id}-1")["status"] == Status.DONE

    retried: list[Exception] = []

    def retry(*_: Any, exc: Exception, **__: Any) -> Exception:
        retried.append(exc)
        return RuntimeError("retry")  # what self.retry raises, once recorded

    def store_down(self: ControlsDeliveryRepository, session_id: str, task_id: str) -> dict[str, Any]:
        raise Unavailable("mongo down")

    monkeypatch.setattr(controls_job.map_controls, "retry", retry)
    monkeypatch.setattr(ControlsDeliveryRepository, "claim_controls_delivery", store_down)
    controls_job.map_controls.apply(args=(record_id, 0), task_id="task-2")
    assert [type(error) for error in retried] == [Unavailable]


def test_a_run_deleted_while_it_is_mapped_ends_its_delivery_quietly(
    mapping_run: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 2026-10-11 (the owner removed old runs while the stack mapped them): the delivery's lease is
    gone, so it stops after the scenario it was on; nothing is raised and nothing is sent."""
    record_id, published = mapping_run["record_id"], mapping_run["published"]

    def publish_then_delete(session_id: str) -> None:
        published.append(session_id)
        get_mongodb()[Collection.SESSIONS].delete_one({"_id": record_id})
        get_mongodb()[Collection.SCENARIOS].delete_many({"session_id": record_id})

    monkeypatch.setattr(controls_job, "publish_session_status", publish_then_delete)
    assert _deliver(record_id, "task-1") == 1 and mapping_run["sent"] == []
