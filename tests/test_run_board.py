"""The status body (owner 2026-10-12): each stage in one word, what to do now, the times, why, and the
numbers, from one pure function over the stored run; and a scenario's controls as the results show them."""

from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.constants import BoardMessage, ControlMatch, RunActionKind, RunKind, Status, Step
from app.core.constants import RunOverall as Overall
from app.core.constants import SessionState as Session
from app.core.constants import StageState as S
from app.data_access.scenario.repository import SESSION_STATUS_FIELDS, session_status_from_record
from app.models.scenario.views import ScenarioCount, SessionStatus, StageTimings
from app.services.scenario.results import build_board, build_scenario_view

_FAILED = {"error": {"code": "unavailable", "message": "The AI service is down."}, "attempts": 3}
#: A run whose first set of 6 (of 10 planned) is written.
_SET = {"planned": 10, "remaining": 4, "written": 6}


def _run(**fields: Any) -> SessionStatus:
    record = {
        "_id": "run-1",
        "entity_id": 86,
        "asset_id": 103,
        "status": Status.QUEUED,
        "step": Step.THREATS,
        "updated_at": datetime.now(UTC),
        "user_id": "u-7",
        "context": {"asset": {"name": "Grid Centre"}},
    }
    return session_status_from_record(record | fields)


def _written(status: Status = Status.DONE, /, **counts: int) -> dict[str, Any]:
    """A run past its threats, its job in `status`, with these scenario counts."""
    return {"status": status, "step": Step.SCENARIOS, "counts": counts}


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        pytest.param(
            {}, (S.PENDING, S.PENDING, S.PENDING, Overall.PENDING, Session.ACTIVE), id="just started"
        ),
        pytest.param(
            {"status": Status.RUNNING, "job": {"attempts": 1}},
            (S.RUNNING, S.PENDING, S.PENDING, Overall.IN_PROGRESS, Session.ACTIVE),
            id="finding threats",
        ),
        pytest.param(
            {"job": {"attempts": 1}},  # given back after an outage: it has started
            (S.RUNNING, S.PENDING, S.PENDING, Overall.IN_PROGRESS, Session.ACTIVE),
            id="threats retried",
        ),
        pytest.param(
            {"status": Status.FAILED, "job": _FAILED},
            (S.ERROR, S.PENDING, S.PENDING, Overall.ERROR, Session.FAILED),
            id="threats failed",
        ),
        pytest.param(
            _written(Status.RUNNING, planned=10),
            (S.COMPLETE, S.RUNNING, S.PENDING, Overall.IN_PROGRESS, Session.ACTIVE),
            id="first set started",
        ),
        pytest.param(
            _written(Status.QUEUED, **_SET, pending=3),
            (S.COMPLETE, S.RUNNING, S.RUNNING, Overall.IN_PROGRESS, Session.ACTIVE),
            id="between two batches",
        ),
        pytest.param(
            _written(**_SET, pending=6, controls_waiting=2),
            (S.COMPLETE, S.COMPLETE, S.RUNNING, Overall.AWAITING_REVIEW, Session.COMPLETED),
            id="set written, controls matching",
        ),
        pytest.param(
            _written(**_SET, accepted=4, rejected=2),
            (S.COMPLETE, S.COMPLETE, S.COMPLETE, Overall.AWAITING_NEXT_SET, Session.COMPLETED),
            id="all reviewed, paths remain",
        ),
        pytest.param(
            _written(planned=6, written=6, accepted=6),
            (S.COMPLETE, S.COMPLETE, S.COMPLETE, Overall.COMPLETE, Session.COMPLETED),
            id="all written and reviewed",
        ),
        pytest.param(
            _written(planned=6, written=6, accepted=6, controls_waiting=1),
            (S.COMPLETE, S.COMPLETE, S.RUNNING, Overall.IN_PROGRESS, Session.COMPLETED),
            id="all reviewed, a regenerated version's controls matching",
        ),
        pytest.param(
            _written(**_SET, pending=6, controls_failed=1),
            (S.COMPLETE, S.COMPLETE, S.ERROR, Overall.AWAITING_REVIEW, Session.COMPLETED),
            id="a control mapping failed",
        ),
        pytest.param(
            _written(planned=0),
            (S.COMPLETE, S.COMPLETE, S.COMPLETE, Overall.COMPLETE, Session.COMPLETED),
            id="no path planned",
        ),
        pytest.param(
            _written(Status.QUEUED, **_SET, accepted=6),
            (S.COMPLETE, S.RUNNING, S.RUNNING, Overall.IN_PROGRESS, Session.ACTIVE),
            id="next set asked",
        ),
        pytest.param(
            _written(Status.FAILED, **_SET) | {"job": _FAILED},
            (S.COMPLETE, S.ERROR, S.COMPLETE, Overall.ERROR, Session.FAILED),
            id="a set failed",
        ),
        pytest.param(
            _written(written=1, accepted=1) | {"kind": RunKind.MANUAL},
            (S.COMPLETE, S.COMPLETE, S.COMPLETE, Overall.COMPLETE, Session.COMPLETED),
            id="hand-written",
        ),
    ],
)
def test_each_stage_and_what_to_do_now(fields: dict[str, Any], expected: tuple[str, ...]) -> None:
    board = build_board(_run(**fields))
    progress = board.progress
    shown = (progress.threats, progress.scenarios, progress.controls, progress.overall, board.session_status)
    assert shown == expected


def test_times_reasons_and_numbers_say_what_happened() -> None:
    """A stage's time once it is complete; why a stage failed or is partial, by stage; the scenario
    numbers."""
    last = {"outcome": "partial", "requested": 6, "delivered": 4}
    fields = _written(planned=170, remaining=162, written=6, pending=6, abandoned=2, controls_waiting=1)
    board = build_board(
        _run(
            **fields,
            timings={"threats_s": 126.1, "scenarios_s": 8.4, "controls_s": 1500.3599999999997},
            plan={"not_assessed": ["Repudiation"]},  # an older run's list: still stored, never shown
            last_next_set=last,
        )
    )
    progress = board.progress
    assert (board.asset_name, board.user_id, progress.last_next_set) == ("Grid Centre", "u-7", last)
    assert progress.timings == StageTimings(threats=126.1, scenarios=8.4, controls=None)  # controls still run
    done = build_board(_run(**_written(**_SET), timings={"controls_s": 1500.3599999999997})).progress
    assert done.timings.controls == 1500.4  # live run 2026-10-12: a sum of many parts, shown to 0.1 s
    assert progress.error_message == {"scenarios": "2 attack path(s) could not be written."}
    assert progress.scenario_count == ScenarioCount(
        total=170, served=6, remaining=162, complete=False, pending_review=6, accepted=0, rejected=0
    )


def test_the_status_reads_nothing_of_the_plan_or_the_systems() -> None:
    """The status is read on every run check and live update: never the plan nor the context's systems."""
    assert not [key for key in SESSION_STATUS_FIELDS if key.startswith(("plan", "context.systems"))]


def test_a_failed_run_says_why_and_a_failed_mapping_names_its_count() -> None:
    failed = build_board(_run(status=Status.FAILED, job=_FAILED)).progress
    assert failed.error_message == {"threats": "The AI service is down."}
    assert failed.scenario_count.total is None and failed.scenario_count.remaining is None
    unmatched = build_board(_run(**_written(**_SET, controls_failed=2))).progress
    assert unmatched.error_message == {"controls": BoardMessage.CONTROLS_FAILED.format(failed=2)}
    # Live E2E 2026-10-15: a hand-written run's controls are never tried again in the background (Rule R1T).
    hand_written = _written(written=1, accepted=1, controls_failed=1) | {"kind": RunKind.MANUAL}
    board = build_board(_run(**hand_written)).progress
    assert board.error_message == {"controls": BoardMessage.CONTROLS_FAILED_MANUAL}
    assert "tried again later" not in board.error_message["controls"]


def test_a_summary_shows_its_own_action_running_or_failed_never_the_one_before() -> None:
    """Review 2026-10-12: a next set's summary is written when it is asked; while it runs, and when its job
    fails (which writes only last_action), the status shows that, never the previous set's "complete"."""
    asked = {"outcome": "running", "requested": 6, "delivered": None}
    for outcome in ("running", "failed"):
        action = {"kind": RunActionKind.NEXT_SET, "outcome": outcome}
        board = build_board(_run(**_written(**_SET), last_action=action, last_next_set=asked))
        assert board.progress.last_next_set == asked | {"outcome": outcome}
    done = {"outcome": "complete", "requested": 6, "delivered": 6}
    regenerating = {"kind": RunActionKind.REGENERATE, "outcome": "running"}
    later = build_board(_run(**_written(**_SET), last_action=regenerating, last_next_set=done)).progress
    assert later.last_next_set == done  # another action runs: the last next set stays as it ended
    # Reviewer 2026-10-12: a next set whose job failed, then a regenerate: it never got its finish write.
    stale = build_board(_run(**_written(**_SET), last_action=regenerating, last_next_set=asked)).progress
    assert stale.last_next_set == asked | {"outcome": "failed"}


def test_a_hand_written_threat_the_library_does_not_hold_is_the_persons() -> None:
    """Review 2026-10-12: a person's new threat (and new type) is never shown as AI-proposed or as a library
    name. G267: v1's words, "unverified", with v1's library block saying where it stands."""
    threat = {
        "type": "Drone intrusion",
        "type_id": None,
        "name": "Rogue drone",
        "library_id": None,
        "ai_generated": False,
    }
    record = {
        "_id": "s1",
        "session_id": "run-1",
        "version": 1,
        "status": "done",
        "source": RunKind.MANUAL,
        "decision": "accepted",
        "content": {"category": "Tampering", "threat": threat},
        "created_at": datetime.now(UTC),
    }
    view = build_scenario_view(record)
    block = view.threat
    assert (block.grounding_status, block.library_threat_type, block.library_threat_name) == (
        "unverified",
        None,
        None,
    )
    assert view.threat_source is None and "AI_PROPOSED_THREAT" not in view.review_flags  # never the AI's
    assert view.library is not None and view.library.threat_type.status == "not_proposed"
    assert (block.threat_type, block.threat_name, block.is_threat_ai_generated) == (
        "Drone intrusion",
        "Rogue drone",
        False,
    )
    # Reviewer 2026-10-12: proposed now, so it has a library id while a curator decides: still the person's.
    pending = record | {"content": {"threat": threat | {"library_id": 901, "library_status": "pending"}}}
    waiting = build_scenario_view(pending)
    assert waiting.threat.grounding_status == "unverified"
    assert waiting.library is not None and waiting.library.threat.status == "inserted"


def test_a_control_shows_its_description_and_why_it_was_kept() -> None:
    """v1's control fields: the description kept with the mapping, the match in capitals and in words."""
    item = {"control_id": 7, "code": "C-7", "name": "Patch", "domain": "Ops", "asset_type": "OT", "rank": 1}
    record = {
        "_id": "s1",
        "session_id": "run-1",
        "version": 1,
        "status": "done",
        "source": RunKind.GENERATED,
        "decision": "rejected",
        "decided_by": "u-7",
        "decided_at": datetime.now(UTC),
        "controls": {
            "status": "done",
            "items": [
                item | {"score": 81.5, "match": ControlMatch.NEAREST, "description": "Apply vendor patches."}
            ],
        },
        "created_at": datetime.now(UTC),
    }
    view = build_scenario_view(record)
    (control,) = view.controls
    assert (control.control_description, control.itot, control.map_rank) == ("Apply vendor patches.", "OT", 1)
    assert control.match_type == "NEAREST" and control.match_reason.startswith("No control reached")
    assert (view.accepted, view.rejected_by, view.accepted_by) == (False, "u-7", None)
    assert (
        view.threat.grounding_status is None and view.scenario.scenario_statement is None
    )  # nothing written
