"""Rules no other test held: the reviewer's impact mismatch, made-up labels and advisory ids in every served
text, the evidence threshold's edge, what another run's register offers the duplicate check, hand-written
targets, asked-slot answers, a scenario read through another run, a regenerate's outage on its last try."""

# ruff: noqa: F811 — the fixtures imported by name are the test parameters of the same name

import dataclasses
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import container
from app.core.constants import (
    AiTask,
    ConflictReason,
    Decision,
    ErrorCode,
    FindingCode,
    Lease,
    RunActionOutcome,
    RunKind,
    TargetProblem,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import check_exact_rules, scenario_id
from app.domain.shared.ask_ai import answers_for_asked_slots
from tests.external_intelligence.evidence.test_evidence_finder import finder_of, one, refs
from tests.external_intelligence.evidence_fakes import ScoredBy, request_of, technique_doc
from tests.test_run_actions import (  # noqa: F401 — api_key and queued are fixtures, used by name
    _identity,
    _regenerate,
    _scenarios,
    _sessions,
    _written_run,
    api_key,
    queued,
)
from tests.test_scenario_writing import _CLEAN, _brief_of, _plan_checked, _plan_threat, _stored
from tests.test_writing_job import _write_batch, chat, sent  # noqa: F401 — fixtures by name

_MADE_UP = "THR7 GHSA-4f8r-qwrm-9x2c MS17-010 VU#123456 ICSMA-23-334-01"
_ADVISORIES = ("GHSA-4f8r-qwrm-9x2c", "MS17-010", "VU#123456", "ICSMA-23-334-01")


def test_a_risk_of_another_impact_is_a_mismatch_that_names_the_impact() -> None:
    """same_impact false alone is the reviewer's blocker, and its message says the impact changed."""
    check, notes = _plan_checked({"rules": {"1": "holds"}, "same_threat": True, "same_impact": False})
    assert [note.code for note in notes] == [FindingCode.SCENARIO_MISMATCH] and not check.same_impact
    assert "the plan's impact:" in notes[0].message


@pytest.mark.parametrize(
    "where",
    [
        {"title": f"Loss of control {_MADE_UP}"},
        {"assumptions": (f"Assumes {_MADE_UP} applies.",)},
        {"why_applies": f"It applies through {_MADE_UP}."},
        {"system_reasons": (("SCADA server", f"It is reached through {_MADE_UP}."),)},
    ],
    ids=["title", "assumptions", "why_applies", "system_reasons"],
)
def test_a_made_up_label_or_advisory_id_is_caught_in_every_served_text(where: dict[str, Any]) -> None:
    """THR<n> and GHSA, MS bulletin, CERT/CC VU# and ICS medical advisory ids the brief never gave."""
    findings = check_exact_rules(dataclasses.replace(_CLEAN, **where), _brief_of(_plan_threat()))
    assert [finding.code for finding in findings] == [FindingCode.UNKNOWN_ID, FindingCode.UNCITED_ADVISORY_ID]
    assert "THR7" in findings[0].message
    assert all(advisory in findings[1].message for advisory in _ADVISORIES)


def test_a_score_equal_to_the_threshold_is_kept() -> None:
    finder, _ = finder_of([technique_doc("T1")], ScoredBy(default=5.0), threshold=5.0)
    assert refs(one(finder, request_of())[0]) == {"T1"}


def test_no_scenario_of_another_run_of_the_same_asset_is_offered_as_a_copy() -> None:
    """D15 (owner 2026-10-20): another run's versions never block a new scenario, whatever their decision;
    only the run's own finished ones are held against it."""
    session_id, scenarios = f"run-{uuid.uuid4().hex}", container.get_threat_scenario_repository()
    scenarios.create_indexes()
    asset = int(uuid.uuid4().hex[:12], 16)
    for decision in (Decision.REJECTED, Decision.ACCEPTED, Decision.PENDING):
        other = _stored(f"{decision}-{session_id}", "p1", asset_id=asset, decision=decision)
        assert scenarios.save_scenario(other)
    own = _stored(session_id, "p2", asset_id=asset)
    assert scenarios.save_scenario(own)
    held = scenarios.list_scenarios_for_duplicate_check(session_id)
    assert [record["_id"] for record in held] == [own["_id"]]


def test_answers_for_asked_slots_names_a_repeated_an_unknown_and_a_missing_slot() -> None:
    answer = {"items": [{"slot": "A", "n": 1}, {"slot": "A", "n": 2}, {"slot": "X"}]}
    kept, problems = answers_for_asked_slots(answer, "items", {"A", "B"})
    assert kept == [{"slot": "A", "n": 1}]
    assert problems == [
        "slot A is unknown or answered twice",
        "slot X is unknown or answered twice",
        "slot B has no answer",
    ]


@pytest.mark.usefixtures("chat", "sent")
def test_regenerate_refuses_a_hand_written_scenario(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]]
) -> None:
    """A person wrote it: there is no plan path to write it again, so nothing is queued."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)
    _scenarios().update_one({"_id": first}, {"$set": {"source": RunKind.MANUAL}})
    answer = _regenerate(client, api_key, record_id, [first])
    assert (answer.status_code, answer.json()["reason"]) == (409, ConflictReason.SCENARIOS_NOT_REGENERABLE)
    assert answer.json()["errors"] == [{"scenario_id": first, "reason": TargetProblem.HAND_WRITTEN}]
    assert queued == []


@pytest.mark.usefixtures("chat", "sent")
def test_a_scenario_of_another_run_of_the_same_entity_is_not_found_through_this_run(
    client: TestClient, api_key: str
) -> None:
    mine, theirs = _written_run(["Threat 1"]), _written_run(["Threat 1"])
    url = f"/v1/sessions/{mine}/scenarios/{scenario_id(theirs, 'p1', 1)}"
    assert client.get(url, headers=_identity(api_key)).status_code == 404
    own = f"/v1/sessions/{mine}/scenarios/{scenario_id(mine, 'p1', 1)}"
    assert client.get(own, headers=_identity(api_key)).status_code == 200


@pytest.mark.usefixtures("sent")
def test_a_regenerate_the_ai_is_down_for_on_its_last_try_keeps_the_old_version_and_ends_partial(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], chat: Any
) -> None:
    """The outage is that path's own: the old version stays current with the reason, nothing is raised."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)

    def down(_: str) -> dict[str, Any]:
        raise Unavailable("down")

    chat.responders[AiTask.WRITE_SCENARIO] = down
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202
    _sessions().update_one({"_id": record_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    lease = JobRepository(_sessions()).claim_job(record_id, 2, TaskName.WRITE_SCENARIOS, "last")
    assert lease is not None and lease.attempts == Lease.MAX_ATTEMPTS
    _write_batch(lease)
    old = _scenarios().find_one({"_id": first})
    assert old["superseded_by"] is None and old["regenerate_error"]["code"] == ErrorCode.UNAVAILABLE
    assert _scenarios().count_documents({"session_id": record_id}) == 1
    run = _sessions().find_one({"_id": record_id})
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL
