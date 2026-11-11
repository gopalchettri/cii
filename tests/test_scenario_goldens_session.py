"""Golden copies of the scenario paperwork: the start checks and frozen context, the review rules, the frozen
plan's progress rules, and the status board and scenario JSON the UI reads, for fixed records. Every answer
here is API behaviour the UI team relies on: none of these files may change."""

import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.core.config import get_settings
from app.core.constants import ContextProperties, Decision, LibraryRowKind, RunActionKind
from app.core.exceptions import AppError, Conflict
from app.domain.scenario import session
from app.domain.scenario.session import build_scenario_view, build_status_board
from app.models.admin.api_clients import Principal
from app.models.library.library import PendingLibraryRow, RejectedLibraryThreat, ThreatLibrary
from app.models.scenario.asset_context import AssetContextRows
from app.models.scenario.views import AcceptRequest, StartRunRequest, session_status_from_record
from app.services.scenario import threat_scenario_service as service_module
from app.services.scenario.threat_scenario_service import ThreatScenarioService
from tests.planner_samples import ACTORS, THREATS
from tests.scenario_goldens import GOLDENS, check_golden

NOW = datetime(2026, 11, 1, 9, 30, tzinfo=UTC)
CARDS = json.loads(
    (GOLDENS / "input_cards.json").read_text(encoding="utf-8"),
    object_hook=lambda row: {key: NOW if value == "<datetime>" else value for key, value in row.items()},
)["cards"]
PLAN = json.loads((GOLDENS / "plan_turns.json").read_text(encoding="utf-8"))["stored"]["plan"]
TRACE = json.loads((GOLDENS / "plan_mixed.json").read_text(encoding="utf-8"))["stored"]["trace"]
CONTROLS = json.loads((GOLDENS / "controls_cards.json").read_text(encoding="utf-8"))["mapped"]
REQUEST = StartRunRequest(asset_id=1206, supporting_system_ids=[1567, 1568], service_id=1624)


def _raised(call: Callable[[], Any]) -> Any:
    """What a call returns, or the API error it raises: its type, status, code, detail, reason, errors."""
    try:
        return {"returned": call()}
    except AppError as error:
        fields = ("status", "code", "detail", "reason", "errors", "details")
        return {"raised": type(error).__name__} | {name: getattr(error, name) for name in fields}


def _errors(call: Callable[[], Any]) -> list[dict[str, Any]]:
    """The ids at fault a review rule names: [] when it lets every id through."""
    try:
        call()
    except Conflict as error:
        return list(error.errors or [])
    return []


_SERVICE_PARTS = (
    "sessions",
    "scenarios",
    "assets",
    "work_control",
    "threats",
    "threat_library",
    "switch",
    "intel_snapshots",
    "audit",
    "send_job",
    "publish_session_status",
)


def _service(**parts: Any) -> ThreatScenarioService:
    """The scenario service on stand-ins: each part a MagicMock unless given."""
    return ThreatScenarioService(**{name: parts.get(name) or MagicMock() for name in _SERVICE_PARTS})


@pytest.fixture(autouse=True)
def _required_facts(monkeypatch: pytest.MonkeyPatch) -> None:
    """The required facts as the goldens were made with, whatever the developer's .env says."""
    monkeypatch.setattr(get_settings(), "asset_properties_required", "sector,data_handled")
    monkeypatch.setattr(get_settings(), "system_properties_required", "past_incidents")


def _asset_row(**changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": 1206,
        "name": "Grid  Centre",
        "category_code": "OT",
        "cii_asset_description": "Runs the grid.",
        "critical_service": "Electricity  supply",
        "sector": "Energy",
        "sub_sector": None,
        "data_handled": "Telemetry",
        "asset_type": "Control system",
        "operating_system": "Windows",
        "target_rto_hours": Decimal(4),
        "asset_priority": 11,
        "entity_technology_context": None,
        "last_review": datetime(2025, 3, 2, 10, 0),
        "never_reviewed": datetime(1900, 1, 1),
        "blob": b"\x00",
    }
    return row | changes


def _system_row(system_id: int, **changes: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": system_id,
        "name": f"System  {system_id}",
        "category_code": "IT",
        "category_name": "IT",
        "past_incidents": "A phishing wave in 2024",
        "technology_used": "[21, 22, 99]",
        "database_platforms": "Oracle, SQL Server",
        "targeted_users": "[x",
        **dict.fromkeys(ContextProperties.SINGLE_SELECT_CODES),
        "hosting_location": 31,
        "managed_by": "7",
        "accessability_channel": "Internet",
        "rto_target_mins": Decimal("30.5"),
    }
    return row | changes


OPTIONS = [
    {"code": "priority", "value": 11, "name": "High"},
    {"code": "technology-used", "value": 21, "name": "Windows"},
    {"code": "technology-used", "value": 22, "name": "Siemens WinCC"},
    {"code": "Hosting-Location", "value": 31, "name": "On premises"},
    {"code": "managed-by", "value": 7, "name": " "},
]


def _rows(
    asset: dict[str, Any] | None = None, systems: list[dict[str, Any]] | None = None, **fields: Any
) -> Any:
    defaults = {
        "asset": _asset_row() if asset is None else asset,
        "services": [{"id": 1624, "name": "Electricity supply", "linked": False}],
        "sector": None,
        "systems": systems
        if systems is not None
        else [_system_row(1567), _system_row(1568), _system_row(1570)],
        "options": copy.deepcopy(OPTIONS),
    }
    return AssetContextRows(**(defaults | fields))


def _frozen(request: StartRunRequest, rows: Any) -> Any:
    context = session.build_run_context(request, rows)
    return {"record": context.to_record(), "missing_facts": context.missing_facts}


def test_golden_session_start_checks_and_frozen_context() -> None:
    no_past = [_system_row(1567, past_incidents=None), _system_row(1568, past_incidents="  ")]
    cases = {
        "frozen": lambda: _frozen(REQUEST, _rows()),
        "asset_not_owned": lambda: _frozen(REQUEST, AssetContextRows(None, [], None, [], [])),
        "system_not_linked": lambda: _frozen(REQUEST, _rows(systems=[_system_row(1567)])),
        "service_unknown": lambda: _frozen(REQUEST, _rows(services=[{"id": 9, "name": "x", "linked": True}])),
        "sector_unknown": lambda: _frozen(REQUEST.model_copy(update={"sector_id": 5}), _rows()),
        "sector_not_parent": lambda: _frozen(
            REQUEST.model_copy(update={"sector_id": 5, "subsector_id": 51}),
            _rows(sector={"id": 51, "name": "Grid", "parent_id": 6, "parent_name": "Power"}),
        ),
        "facts_missing": lambda: _frozen(
            REQUEST, _rows(asset=_asset_row(data_handled=None), systems=no_past)
        ),
        "head_missing": lambda: _frozen(REQUEST, _rows(systems=[{"id": 1567}, {"id": 1568}])),
        "reserved_name": lambda: _frozen(REQUEST, _rows(asset=_asset_row(alias="x"))),
        "options_shape": lambda: _frozen(REQUEST, _rows(options=[{"code": "priority", "label": "High"}])),
        "required_not_returned": lambda: _frozen(
            REQUEST, _rows(asset={k: v for k, v in _asset_row().items() if k != "data_handled"})
        ),
    }
    check_golden("session_start", {name: _raised(case) for name, case in cases.items()})


def _replayed(earlier: dict[str, Any]) -> None:
    """The service's replay check of `earlier`, the run that took the key."""
    sessions = MagicMock()
    sessions.get.return_value = earlier
    _service(sessions=sessions)._replay(PRINCIPAL, REQUEST, "key-1", False)


def _intel_checked(snapshot: dict[str, Any]) -> None:
    """The service's check that the active intelligence snapshot holds data, intelligence on."""
    switch, snapshots = MagicMock(), MagicMock()
    switch.is_on.return_value, snapshots.get.return_value = True, snapshot
    _service(switch=switch, intel_snapshots=snapshots)._refuse_without_intel_data()


def test_golden_session_replay_fingerprint_and_intel_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "session_status_from_record", lambda record: None)
    fingerprint = REQUEST.fingerprint()
    earlier = {"asset_id": 1206, "kind": "generated", "request_hash": fingerprint}
    cases = {
        "same": earlier,
        "manual": earlier | {"kind": "manual"},
        "other_asset": earlier | {"asset_id": 7},
        "other_body": earlier | {"request_hash": "x"},
        "no_hash": {"asset_id": 1206, "kind": "generated"},
    }
    replays = {name: _raised(lambda e=e: _replayed(e)) for name, e in cases.items()}
    intel = {
        "none": _raised(lambda: _intel_checked({})),
        "indexed": _raised(lambda: _intel_checked({"counts": {"indexed": 3}})),
    }
    check_golden("session_replay", {"fingerprint": fingerprint, "replays": replays, "intel": intel})


def _session(**fields: Any) -> dict[str, Any]:
    record = {
        "_id": "run-golden-1",
        "entity_id": 86,
        "asset_id": 103,
        "status": "done",
        "step": "scenarios",
        "updated_at": NOW,
        "user_id": "u-1",
        "context": {"asset": {"name": "Grid Control Centre"}},
        "counts": {"planned": 6, "written": 6, "remaining": 0, "pending": 0, "accepted": 2, "rejected": 1},
        "timings": {"threats_s": 12.34, "scenarios_s": 50.06, "controls_s": 3.21},
        "job": {"attempts": 1, "epoch": 2},
    }
    return record | fields


SESSIONS = {
    "queued_first": _session(status="queued", step="threats", job={"attempts": 0, "epoch": 1}),
    "finding_threats": _session(
        status="running",
        step="threats",
        job={
            "attempts": 2,
            "epoch": 1,
            "retry": {
                "reason": "ai_busy",
                "message": "The AI is busy.",
                "attempt": 2,
                "max_attempts": 5,
                "retry_at": NOW,
            },
        },
    ),
    "writing": _session(status="running", counts={"planned": 6, "written": 2, "remaining": 4, "pending": 2}),
    "awaiting_review": _session(counts={"planned": 6, "written": 6, "pending": 3}),
    "awaiting_next_set": _session(counts={"planned": 12, "written": 6, "remaining": 6}),
    "outage_cards": _session(counts={"planned": 6, "written": 5, "outage_cards": 1, "abandoned": 1}),
    "failed_finding": _session(
        status="failed",
        step="threats",
        job={
            "attempts": 5,
            "epoch": 1,
            "error": {"code": "unavailable", "message": "The AI is busy.", "reason": "ai_busy"},
        },
    ),
    "failed_writing": _session(
        status="failed",
        job={
            "attempts": 5,
            "epoch": 3,
            "error": {"code": "job_abandoned", "message": "Abandoned.", "reason": "worker_stopped"},
        },
    ),
    "cancelled_finding": _session(
        status="cancelled", step="threats", cancelled={"user_id": "u-2", "at": NOW}
    ),
    "mapping_controls": _session(
        counts={"planned": 6, "written": 6, "controls_waiting": 2},
        controls_delivery={
            "retry": {
                "reason": "ai_busy",
                "message": "The AI is busy.",
                "attempt": 1,
                "max_attempts": 4,
                "retry_at": NOW,
            }
        },
    ),
    "controls_failed_manual": _session(kind="manual", counts={"written": 1, "controls_failed": 1}),
    "controls_cancelled": _session(
        counts={"planned": 6, "written": 6, "controls_cancelled": 2}, cancelled={"user_id": "u-2", "at": NOW}
    ),
    "next_set_running": _session(
        status="running",
        last_action={"kind": "next_set", "outcome": "running"},
        last_next_set={"outcome": "running", "requested": 6, "epoch": 3},
    ),
    "regen_failed": _session(
        last_action={"kind": "next_set", "outcome": "complete"},
        last_regen={"outcome": "running", "requested": 2, "epoch": 4},
    ),
}


def test_golden_session_status_boards() -> None:
    boards = {
        name: build_status_board(session_status_from_record(record)) for name, record in SESSIONS.items()
    }
    check_golden("session_boards", boards)


def _with_controls(card: dict[str, Any], **controls: Any) -> dict[str, Any]:
    record = next(mapped["record"] for mapped in CONTROLS if mapped["path_id"] == card["path_id"])
    return card | {"controls": record | {"status": "done", "attempts": 1} | controls}


def _views() -> dict[str, Any]:
    done, story = CARDS[0], CARDS[4]
    failed = {
        "_id": "f-1",
        "session_id": "run-golden-1",
        "path_id": "p9",
        "version": 1,
        "status": "failed",
        "source": "generated",
        "decision": "pending",
        "created_at": NOW,
        "content": {"category": "Spoofing"},
        "findings": [],
        "failure": {"code": "unavailable", "message": "The AI is busy.", "reason": "ai_busy"},
    }
    manual = done | {
        "source": "manual",
        "content": done["content"]
        | {
            "threat": done["content"]["threat"]
            | {"library_id": None, "library_status": "pending", "type_id": None}
        },
    }
    cards = {
        "done_pending": done,
        "story_accepted": _with_controls(story)
        | {"decision": "accepted", "decided_by": "u-1", "decided_at": NOW},
        "rejected_controls_failed": done
        | {
            "decision": "rejected",
            "decided_by": "u-3",
            "decided_at": NOW,
            "controls": {"status": "failed", "attempts": 5, "error": {"code": "x"}},
        },
        "controls_queued": done
        | {"controls": {"status": "queued", "attempts": 2, "error": {"code": "busy"}}},
        "outage_card": failed,
        "blocked": done
        | {
            "status": "blocked",
            "findings": [{"code": "unknown_id", "severity": "blocker", "message": "Made up SYS1."}],
        },
        "manual_pending": manual,
        "manual_rejected": manual
        | {
            "content": manual["content"]
            | {"threat": manual["content"]["threat"] | {"library_status": "curator_rejected"}}
        },
        "with_warning_and_note": done
        | {
            "findings": [
                {"code": "citation_removed", "severity": "warning", "message": "w"},
                {"code": "plan_check", "severity": "note", "message": "n"},
            ]
        },
        "regenerated": done
        | {"version": 2, "generation": {"epoch": 4, "started_at": NOW, "finished_at": NOW}},
    }
    views = {name: build_scenario_view(card) for name, card in cards.items()}
    views["with_history"] = build_scenario_view(cards["regenerated"], "other-accepted", [done])
    return views


def test_golden_session_scenario_views() -> None:
    check_golden("session_views", _views())


def _target(sid: str, path: str, **fields: Any) -> dict[str, Any]:
    base = {
        "_id": sid,
        "path_id": path,
        "source": "generated",
        "status": "done",
        "decision": "pending",
        "superseded_by": None,
        "content": {"threat": {"library_id": 1, "ai_generated": False}},
        "controls": {"status": "done"},
    }
    return base | fields


TARGETS = {
    "a": _target("a", "p1"),
    "b": _target("b", "p2", decision="accepted"),
    "c": _target("c", "p3", decision="rejected"),
    "d": _target("d", "p4", status="failed", failure={"reason": "ai_busy"}),
    "e": _target("e", "p5", status="failed", failure={"reason": None}),
    "f1": _target("f1", "p6"),
    "f2": _target("f2", "p6", superseded_by="f3"),
    "g": _target("g", "p7", content={"threat": {"library_id": 99, "ai_generated": False}}),
    "h": _target("h", "p8", content={"threat": {"library_id": None, "ai_generated": True}}, controls={}),
    "m": _target("m", "p9", source="manual"),
}
PRINCIPAL = Principal(client_id="c-1", user_id="u-1", entity_id=86, tenant_id="t-1")


def _controls_pending(scenario_ids: list[str]) -> list[str]:
    """The ids an accept of `scenario_ids` reports as still waiting for their controls."""
    scenarios = MagicMock()
    scenarios.list.side_effect = lambda fields, **where: (
        [TARGETS[sid] for sid in where["scenario_id_in"]] if fields == "target" else []
    )
    scenarios.update_scenario_decisions.side_effect = lambda ids, *rest: len(ids)
    library = ThreatLibrary((), (), threats_without_category=(1,))
    service = _service(scenarios=scenarios, threat_library=lambda: library)
    run = session_status_from_record(_session())
    accepted = service.accept_threat_scenarios(PRINCIPAL, run, AcceptRequest(scenario_ids=scenario_ids))
    return accepted.controls_pending


def _nothing_to_accept() -> None:
    """The service's accept-all on a run with no written scenario."""
    scenarios = MagicMock()
    scenarios.list.return_value = []
    _service(scenarios=scenarios)._everything_acceptable("run-golden-1")


def _resumes_cancelled_controls(record: dict[str, Any]) -> bool:
    """Whether a regenerate queued on the run resumes the controls a cancel stopped."""
    sessions, work_control, switch = MagicMock(), MagicMock(), MagicMock()
    sessions.update_scenario_session_job.return_value = None
    work_control.resume_scenario_controls.return_value = 0
    switch.is_on.return_value = False
    service = _service(sessions=sessions, work_control=work_control, switch=switch)
    service._queue_write_job(PRINCIPAL, session_status_from_record(record), RunActionKind.REGENERATE, [])
    return bool(work_control.resume_scenario_controls.called)


def _cancel_seen(record: dict[str, Any]) -> Any:
    """The cancel stamp a next set with no path left resumes the stopped controls under."""
    sessions, work_control = MagicMock(), MagicMock()
    sessions.get.return_value = {"plan": {"paths": []}}
    work_control.resume_scenario_controls.return_value = 1
    service = _service(sessions=sessions, work_control=work_control)
    service.write_next_threat_scenario_set(PRINCIPAL, session_status_from_record(record))
    return work_control.resume_scenario_controls.call_args.args[1]


def test_golden_session_review_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_module, "utc_now", lambda: NOW)
    monkeypatch.setattr(service_module, "uuid", SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="d-9")))
    ids = ["a", "b", "c", "d", "e", "f1", "g", "h", "x"]
    known = {1, 2, 3}
    run = session_status_from_record(_session())
    review_open = {
        name: _raised(lambda r=r: session.check_session_ready_for_review(session_status_from_record(r)))
        for name, r in SESSIONS.items()
    }
    cancelled = [_resumes_cancelled_controls(record) for record in SESSIONS.values()]
    controls_pending = _controls_pending(["a", "h"])
    stamp = service_module._new_decided_stamp(PRINCIPAL)
    monkeypatch.setattr(
        service_module, "check_session_ready_for_review", lambda run: None
    )  # every run's cancel stamp
    outcome = {
        "accept": _errors(lambda: session.get_scenarios_to_decide(ids, TARGETS, Decision.ACCEPTED, known)),
        "reject": _errors(lambda: session.get_scenarios_to_decide(ids, TARGETS, Decision.REJECTED, known)),
        "decidable": _raised(
            lambda: session.get_scenarios_to_decide(["a", "h"], TARGETS, Decision.ACCEPTED, known)
        ),
        "not_decidable": _raised(
            lambda: session.get_scenarios_to_decide(ids, TARGETS, Decision.ACCEPTED, known)
        ),
        "accept_all": session.pick_scenarios_for_accept_all(list(TARGETS.values()), {"p1": "zz"}, known),
        "replace_off": _raised(
            lambda: session.find_versions_to_replace([TARGETS["a"]], {"p1": "old"}, False)
        ),
        "replace_on": session.find_versions_to_replace([TARGETS["a"]], {"p1": "old"}, True),
        "outcome": session.read_decision_results(
            ["a", "b", "h"],
            ["a", "h"],
            {"a": {"decision": "accepted", "decision_id": "d1"}, "h": {"decision": "pending"}},
            Decision.ACCEPTED,
            "d1",
        ),
        "regenerate": _errors(lambda: session.build_regenerate_batch(ids + ["m", "f2"], TARGETS)),
        "regenerate_batch": _raised(lambda: session.build_regenerate_batch(["a", "d"], TARGETS)),
        "not_regenerable": _raised(lambda: session.build_regenerate_batch(["e", "m"], TARGETS)),
        "controls_pending": controls_pending,
        "stamp": stamp,
        "nothing_to_accept": _raised(_nothing_to_accept),
        "cancelled": cancelled,
        "cancel_seen": [_cancel_seen(record) for record in SESSIONS.values()],
        "open": review_open,
        "owner": [
            _raised(lambda: session.get_session_owned_by_caller(None, "s", 86)),
            _raised(lambda: session.get_session_owned_by_caller({"entity_id": 9}, "s", 86)),
            _raised(lambda: session.get_session_owned_by_caller({"entity_id": 86}, "s", 86)),
        ],
        "run": run.session_id,
    }
    check_golden("session_review", outcome)


def _paths() -> list[dict[str, Any]]:
    paths = copy.deepcopy(PLAN["paths"])
    paths[0] |= {"served": "s-1"}
    paths[1] |= {"abandoned": True, "attempts": 2, "abandoned_reason": "ai_busy"}
    paths[2] |= {"attempts": 1}
    paths[3] |= {
        "abandoned": True,
        "attempts": 1,
        "abandoned_reason": "unknown_id",
        "replaced_by": paths[5]["path_id"],
        "selected": False,
        "unselected_reason": "replaced_after_failure",
    }
    paths[5] |= {"selected": True, "unselected_reason": None, "replaces": paths[3]["path_id"]}
    return paths


def _nothing_left(paths: list[dict[str, Any]]) -> None:
    """The service's next set on run-1 when no path is asked for and no stopped control is resumed."""
    sessions, work_control = MagicMock(), MagicMock()
    sessions.get.return_value = {"plan": {"paths": paths}}
    work_control.resume_scenario_controls.return_value = 0
    run = session_status_from_record(_session(_id="run-1"))
    _service(sessions=sessions, work_control=work_control).write_next_threat_scenario_set(PRINCIPAL, run)


def test_golden_session_plan_progress_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    paths, threats = _paths(), {threat["key"]: threat for threat in PLAN["threats"]}
    in_set = [path["path_id"] for path in paths[:4]]
    budget = [  # a reserve is picked only while the set's budget lasts
        session.pick_replacement_path(paths, threats, in_set) is not None,
        session.pick_replacement_path(paths, threats, in_set[:1]) is not None,
    ]
    monkeypatch.setattr(get_settings(), "next_set_size", 0)  # no path asked for: why none is left
    outcome = {
        "next_set": session.pick_next_paths_to_write(paths, 6),
        "next_batch": session.pick_next_paths_to_write(paths)[1],
        "counts": session.count_plan_paths(paths),
        "why_none": [session.find_why_no_path_left(paths), session.find_why_no_path_left(PLAN["paths"])],
        "summary": session.summarise_finished_set(paths[:4], paths, "partial"),
        "reserve": session.pick_replacement_path(paths, threats, in_set),
        "budget": budget,
        "still": [session.is_still_to_write(path, reopen) for path in paths for reopen in (False, True)],
        "nothing_left": _raised(lambda: _nothing_left(paths)),
        "trace_view": session.build_plan_trace_view("run-golden-1", TRACE, paths),
    }
    check_golden("session_progress", outcome)


def test_golden_session_library_lookups() -> None:
    library = ThreatLibrary(
        THREATS,
        ACTORS,
        pending=(PendingLibraryRow(LibraryRowKind.THREAT, 77, "Operator account takeover", 5),),
        curator_rejected=(RejectedLibraryThreat(78, "Badge cloning", 2),),
        threats_without_category=(91,),
    )
    names = [
        "Phishing steals operator credentials",
        "T-12 Operator account takeover",
        "Badge  cloning",
        "New one",
    ]
    outcome = {
        "named": {name: session.find_library_threat_by_name(library, name) for name in names},
        "known": session.list_active_or_pending_threat_ids(library),
    }
    check_golden("session_library", outcome)
