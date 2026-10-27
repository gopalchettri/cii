"""The scenario write job (Step 12, BUILD_PLAN S25-S26): batches of six, saved one by one, handed on by
themselves to the end of the set a person asked for; on the test MongoDB, with a fake chat model."""

import json
import threading
import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from celery.exceptions import Ignore
from prometheus_client import REGISTRY
from structlog.testing import capture_logs

from app import container
from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AI_PATH_OUTAGE_MESSAGE,
    ActorRole,
    AiOutage,
    AiTask,
    Collection,
    ErrorCode,
    Lease,
    LogEvent,
    RunActionOutcome,
    ScenarioStatus,
    Status,
    TaskName,
    UnselectedReason,
)
from app.core.database import get_mongodb
from app.core.exceptions import JobFailed, LeaseLost, Unavailable
from app.data_access.jobs.job_repository import JobLease, JobRepository
from app.domain.scenario.plan import next_paths_to_write, next_set_paths, planned_threat_record
from app.models.scenario.plan import PlannedActor
from app.worker import jobs
from app.worker.scenario import plan_progress, write_job
from app.worker.scenario.write_job import ScenarioWriteJob
from tests.fakes import FakeChatModel
from tests.planner_samples import CONTEXT, planned

_ACTORS = (PlannedActor(7, "Cybercriminal", ActorRole.ACTING),)
_CONSISTENT = {"rules": {"1": "holds"}, "same_threat": True, "same_impact": True}
#: Every live update the job sends (the runs it names).
PUBLISHED: list[str] = []


def _sessions() -> Any:
    return get_mongodb()[Collection.SESSIONS]


def _queued_run(
    threat_names: list[str], systems: tuple[int, ...] = (321,), first_set: int | None = None, limit: int = 0
) -> str:
    """A run planned with one path per threat, every path selected, or with a `limit` (TOTAL_SCENARIO_COUNT)
    the first `limit` (the rest kept as reserves, target_reached); its set (job.set) is every selected path,
    or the first `first_set` (INITIAL_SET_SIZE), and its batch that set's first six."""
    record_id = uuid.uuid4().hex
    threats = [
        planned_threat_record(
            planned(f"lib:{number}", name, systems=systems, actors=_ACTORS, reason="It applies.")
        )
        for number, name in enumerate(threat_names, start=1)
    ]
    paths = [
        {
            "path_id": f"p{rank}",
            "rank": rank,
            "selected": not limit or rank <= limit,
            "unselected_reason": None if not limit or rank <= limit else UnselectedReason.TARGET_REACHED,
            "served": None,
            "attempts": 0,
            "abandoned": False,
            "steps": [threat["key"]],
            "systems": threat["systems"],
            "category": "Tampering",
            "categories": ["Tampering"],
        }
        for rank, threat in enumerate(threats, start=1)
    ]
    asked = next_set_paths(paths, len(paths) if first_set is None else first_set)
    batch = next_paths_to_write(path for path in paths if path["path_id"] in asked)
    now = datetime.now(UTC)
    _sessions().insert_one(
        {
            "_id": record_id,
            "entity_id": 86,
            "asset_id": int(record_id[:6], 16),  # its own asset: one active run per asset is enforced
            "status": Status.QUEUED,
            "active": True,
            "context": CONTEXT.to_record(),
            "plan": {
                "threats": threats,
                "paths": paths,
                "target": limit,
                "not_assessed": [],
                "frozen_at": now,
            },
            "job": {
                "task": TaskName.WRITE_SCENARIOS,
                "epoch": 1,
                "attempts": 0,
                "due_at": now,
                "batch": batch,
                "set": asked,
            },
            "updated_at": now,
        }
    )
    return record_id


def _answer_for(user_prompt: str) -> dict[str, Any]:
    """A clean scenario for the brief it is given; every one gets the same title, so titles must be made
    unique, and its own statement (the very same words are a copy whatever the threat: G268). A threat named
    "Unreadable ..." always gets an answer missing its texts."""
    brief = json.loads(user_prompt.removeprefix("BRIEF:\n"))
    options = brief["entry_point_options"]
    answer = {
        "scenario_title": "Loss of control integrity",
        "scenario_statement": f"A cybercriminal could tamper with {options[0] if options else 'it'} at Grid "
        f"Control Centre in a {brief['threat']['threat']} attack.",
        "risk_statement": "Loss of trusted control at Grid Control Centre could interrupt transmission.",
        "assumptions": [],
        "entry_point": options[0] if options else "",
    }
    return {"scenario_title": "x"} if brief["threat"]["threat"].startswith("Unreadable") else answer


def write_job_with(chat: FakeChatModel, library: Any) -> ScenarioWriteJob:
    """The write job as the app builds it, writing with `chat` from `library`."""
    return ScenarioWriteJob(
        sessions=container.get_threat_scenario_session_repository(),
        scenarios=container.get_threat_scenario_repository(),
        chat=chat,
        threat_library=lambda: library,
        switch=container.get_intelligence_switch(),
        evidence_finder=container.get_evidence_finder,
        feeds=container.get_intel_feed_repository(),
        audit=container.get_audit_repository(),
    )


@pytest.fixture
def chat(monkeypatch: pytest.MonkeyPatch) -> FakeChatModel:
    fake = FakeChatModel()
    fake.responders[AiTask.WRITE_SCENARIO] = _answer_for
    fake.responders[AiTask.PLAN_CHECK] = lambda _: _CONSISTENT
    actors = SimpleNamespace(
        actors=(SimpleNamespace(actor_id=7, name="Cybercriminal"),),
        threats=[SimpleNamespace(catalogue_id=number, type_id=1) for number in range(1, 30)],
    )
    job = write_job_with(fake, actors)
    monkeypatch.setattr(container, "get_scenario_write_job", lambda: job)
    monkeypatch.setattr(plan_progress, "publish_session_status", PUBLISHED.append)
    return fake


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    sends: list[tuple[Any, ...]] = []
    monkeypatch.setattr(jobs, "send_job", lambda *args, **_priority: sends.append(args))
    monkeypatch.setattr(write_job, "send_job", lambda *args: sends.append(args))  # the controls messages
    return sends


def _write_batch(lease: JobLease | None) -> None:
    """One delivery of the write job, as its task runs it."""
    container.get_scenario_write_job().write_scenario_batch(lease)  # type: ignore[arg-type]


def _deliver_until_done(record_id: str) -> int:
    """Each message the job sends itself, delivered in turn, until the run ends: the number of deliveries."""
    deliveries = 0
    while (
        lease := JobRepository(_sessions()).claim_job(
            record_id, 1, TaskName.WRITE_SCENARIOS, f"d{deliveries}"
        )
    ) is not None:
        deliveries += 1
        _write_batch(lease)
    return deliveries


def _settled(outcome: str) -> float:
    return REGISTRY.get_sample_value("tsg_scenarios_total", {"outcome": outcome}) or 0.0


def _scenarios_of(record_id: str) -> list[dict[str, Any]]:
    return list(get_mongodb()[Collection.SCENARIOS].find({"session_id": record_id}).sort("path_id", 1))


def test_fourteen_paths_are_written_in_three_batches_by_themselves(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """T-WRT-20 (S25-S26): 6 + 6 + 2, each batch handed on in a fenced write; one title per scenario; the run
    ends complete, its counts from the scenarios."""
    container.get_threat_scenario_repository().create_indexes()
    record_id = _queued_run([f"Threat {number}" for number in range(1, 15)])
    written_before = _settled("written")
    assert _deliver_until_done(record_id) == 3
    # Each batch hands the next to itself (2); each scenario sends a controls message as it is saved and each
    # batch one more ("card first, controls later", S34): reviewers see the scenarios while they are mapped.
    assert [task for task, _, _ in sent].count(TaskName.WRITE_SCENARIOS) == 2
    assert [task for task, _, _ in sent].count(TaskName.MAP_CONTROLS) == 14 + 3
    assert _settled("written") == written_before + 14  # S27: tsg_scenarios_total{outcome}
    assert PUBLISHED.count(record_id) == 14  # T-WRT-19: a live update after every save
    run, stored = _sessions().find_one({"_id": record_id}), _scenarios_of(record_id)
    assert (run["status"], run["active"], run["last_action"]["outcome"]) == (
        Status.DONE,
        False,
        RunActionOutcome.COMPLETE,
    )
    assert {key: run["counts"][key] for key in ("planned", "written", "remaining", "abandoned")} == {
        "planned": 14,
        "written": 14,
        "remaining": 0,
        "abandoned": 0,
    }
    titles = [scenario["content"]["title"] for scenario in stored]
    assert len(set(titles)) == 14 and sum(title.endswith(")") for title in titles) == 13
    assert all(path["served"] for path in run["plan"]["paths"])
    assert {scenario["controls"]["status"] for scenario in stored} == {Status.QUEUED}


def test_the_run_writes_only_its_first_set_and_the_rest_wait_for_a_next_set(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """G196 (owner 2026-10-11, as v1): a plan of 8 with INITIAL_SET_SIZE 3 writes the 3 best-ranked paths and
    ends the action; the other 5 wait for a next set, nothing handed on."""
    record_id = _queued_run([f"Threat {number}" for number in range(1, 9)], first_set=3)
    assert _deliver_until_done(record_id) == 1
    assert [task for task, _, _ in sent].count(TaskName.WRITE_SCENARIOS) == 0
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["active"], run["last_action"]["outcome"]) == (
        Status.DONE,
        False,
        RunActionOutcome.COMPLETE,
    )
    assert [path["path_id"] for path in run["plan"]["paths"] if path["served"]] == ["p1", "p2", "p3"]
    assert (run["counts"]["written"], run["counts"]["remaining"]) == (3, 5)


def test_a_job_with_no_set_writes_its_batch_and_stops(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """G196: a run queued before sets existed has no job.set: it writes the batch in its job, then stops; the
    rest waits for a next set (never a crash, never the whole plan)."""
    record_id = _queued_run([f"Threat {number}" for number in range(1, 9)])
    _sessions().update_one({"_id": record_id}, {"$unset": {"job.set": ""}})
    assert _deliver_until_done(record_id) == 1
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["counts"]["written"], run["counts"]["remaining"]) == (Status.DONE, 6, 2)


def test_a_set_ends_complete_though_an_earlier_set_abandoned_a_path(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """G196: an action's outcome is its own set's; a path set 1 gave up on is no failure of set 2."""
    record_id = _queued_run(["Old threat", "Next threat"], first_set=2)
    _sessions().update_one(
        {"_id": record_id},
        {"$set": {"plan.paths.0.abandoned": True, "job.set": ["p2"], "job.batch": [{"path_id": "p2"}]}},
    )
    _deliver_until_done(record_id)
    assert _sessions().find_one({"_id": record_id})["last_action"]["outcome"] == RunActionOutcome.COMPLETE


@pytest.mark.parametrize("older_plan", [{}, {"not_assessed": ["Spoofing"]}])
def test_a_set_is_partial_only_when_one_of_its_paths_was_given_up(older_plan: dict[str, Any]) -> None:
    """A plan with no not_assessed list, or one an older release saved with a category in it, ends
    complete."""
    changes: dict[str, Any] = {}
    path = {"path_id": "p1", "rank": 1, "selected": True, "served": "s1", "abandoned": False, "attempts": 0}
    plan = {"paths": [path], "frozen_at": datetime.now(UTC)} | older_plan
    lease = SimpleNamespace(update_job=changes.update)
    run = {"_id": "r", "plan": plan, "job": {"set": ["p1"]}}
    sessions, scenarios = (
        container.get_threat_scenario_session_repository(),
        container.get_threat_scenario_repository(),
    )
    plan_progress.PlanProgress(lease, run, sessions, scenarios).continue_or_finish()  # type: ignore[arg-type]
    assert changes["last_action.outcome"] == RunActionOutcome.COMPLETE


def test_an_unreadable_path_is_abandoned_at_once_and_the_run_ends_partial(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """T-WRT-21 (S25-S26): a visible failure card; the writer's own retry is off, so the path is abandoned
    after its first attempt and never written again."""
    record_id = _queued_run(["Good threat", "Unreadable threat"])
    failed_before, abandoned_before = _settled("failed"), _settled("abandoned")
    assert _deliver_until_done(record_id) == 1
    assert (_settled("failed"), _settled("abandoned")) == (failed_before + 1, abandoned_before + 1)
    run = _sessions().find_one({"_id": record_id})
    bad = next(path for path in run["plan"]["paths"] if path["path_id"] == "p2")
    assert (bad["attempts"], bad["abandoned"], bad["served"]) == (1, True, None)
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL and run["counts"]["abandoned"] == 1
    card = _scenarios_of(record_id)[1]
    assert (card["status"], card["failure"]["code"]) == (ScenarioStatus.FAILED, ErrorCode.GENERATION_FAILED)
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 1 + 2  # the good path, the unreadable one and its repair


def test_a_path_the_plan_cannot_support_is_abandoned_at_once(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    record_id = _queued_run(["Threat on a removed system"], systems=(999,))
    assert _deliver_until_done(record_id) == 1 and chat.calls == []
    run = _sessions().find_one({"_id": record_id})
    assert run["plan"]["paths"][0]["abandoned"] and run["plan"]["paths"][0]["attempts"] == 1
    assert _scenarios_of(record_id)[0]["failure"]["code"] == ErrorCode.INVALID_PLAN


def test_a_threat_retired_since_the_plan_is_abandoned_with_no_ai_call(
    chat: FakeChatModel, sent: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Owner, 2026-10-10: the library a curator edits mid-run is read for every batch."""
    library = SimpleNamespace(
        actors=(SimpleNamespace(actor_id=7, name="Cybercriminal"),),
        threats=[SimpleNamespace(catalogue_id=2, type_id=1)],  # threat 1 retired after the plan
    )
    monkeypatch.setattr(container, "get_scenario_write_job", lambda: write_job_with(chat, library))
    record_id = _queued_run(["Retired threat", "Live threat"])
    assert _deliver_until_done(record_id) == 1
    run, stored = _sessions().find_one({"_id": record_id}), _scenarios_of(record_id)
    assert [path["abandoned"] for path in run["plan"]["paths"]] == [True, False]
    assert stored[0]["failure"]["code"] == ErrorCode.LIBRARY_RECORD_RETIRED and stored[1]["status"] == "done"
    assert (
        len(chat.asked(AiTask.WRITE_SCENARIO)) == 1
        and run["last_action"]["outcome"] == RunActionOutcome.PARTIAL
    )


def test_an_outage_saves_the_others_and_the_retry_skips_what_was_saved(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """T-WRT-13 (S25): the job is given back; the written paths cost no AI call again."""
    record_id = _queued_run(["Threat 1", "Threat 2", "Threat 3"])
    down = {"once": True}

    def down_once(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt and down.pop("once", False):
            raise Unavailable("AI down")
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = down_once
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    assert len(_scenarios_of(record_id)) == 2
    asked_before = len(chat.asked(AiTask.WRITE_SCENARIO))
    assert _deliver_until_done(record_id) == 1
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == asked_before + 1 and len(_scenarios_of(record_id)) == 3


def test_a_retry_after_a_crash_still_sends_the_written_scenarios_controls_message(
    chat: FakeChatModel, sent: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review 2026-10-11: a delivery that saved every path, then died before its controls message, left the
    retry nothing to write, so nothing was sent: the controls waited for the sweep (up to 35 minutes)."""
    record_id = _queued_run(["Threat 1", "Threat 2"])

    def dies(*_: Any) -> None:
        if len(_scenarios_of(record_id)) == 2:  # every path saved: it dies before the next message
            raise RuntimeError("the worker died")

    monkeypatch.setattr(write_job, "send_job", dies)
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(RuntimeError):
        _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    assert len(_scenarios_of(record_id)) == 2
    monkeypatch.setattr(write_job, "send_job", lambda *args: sent.append(args))
    asked = len(chat.asked(AiTask.WRITE_SCENARIO))
    assert _deliver_until_done(record_id) == 1 and len(chat.asked(AiTask.WRITE_SCENARIO)) == asked
    assert [task for task, _, _ in sent].count(TaskName.MAP_CONTROLS) == 1


def test_a_blocked_scenario_is_kept_hidden_and_its_path_given_up_at_once(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """T-WRT-10 (S25): a blocked draft hides the scenario, counts as an attempt and gives its path up."""

    def cites_an_advisory(user_prompt: str) -> dict[str, Any]:
        answer = _answer_for(user_prompt)
        return answer | {"scenario_statement": answer["scenario_statement"] + " CVE-2024-1234 helps."}

    chat.responders[AiTask.WRITE_SCENARIO] = cites_an_advisory
    record_id = _queued_run(["Threat 1"])
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first"))
    run, stored = _sessions().find_one({"_id": record_id}), _scenarios_of(record_id)
    assert stored[0]["status"] == ScenarioStatus.BLOCKED and "controls" not in stored[0]
    path = run["plan"]["paths"][0]
    assert (path["attempts"], path["abandoned"], run["counts"]["written"]) == (1, True, 0)
    assert path["last_blocker"] == path["abandoned_reason"] == "uncited_advisory_id"
    assert run["status"] == Status.DONE and run["last_action"]["outcome"] == RunActionOutcome.PARTIAL


def _on_last_try(record_id: str) -> JobLease:
    _sessions().update_one({"_id": record_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "last")
    assert lease is not None and lease.attempts == Lease.MAX_ATTEMPTS
    return lease


def test_a_path_the_ai_keeps_failing_on_gets_a_card_and_the_run_goes_on(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """Review fix 4: on the job's last try, with another path of the batch written, the outage is that path's
    own: a failure card and an attempt, and the path is left to the next set; the run no longer fails."""

    def threat_two_times_out(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt:
            raise Unavailable("timed out")
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = threat_two_times_out
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _write_batch(_on_last_try(record_id))
    run, stored = _sessions().find_one({"_id": record_id}), _scenarios_of(record_id)
    assert stored[1]["failure"]["code"] == ErrorCode.UNAVAILABLE and run["plan"]["paths"][1]["attempts"] == 1
    assert not run["plan"]["paths"][1]["abandoned"] and run["status"] == Status.DONE


def test_a_path_the_ai_timed_out_on_gets_a_card_that_names_the_outage(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """Owner 2026-10-20: the card says the AI timed out (with its reason), not only that it did not answer; an
    outage that names none keeps the plain message."""

    def two_and_three_fail(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt:
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT], reason=AiOutage.TIMED_OUT)
        if '"Threat 3"' in user_prompt:
            raise Unavailable("down")
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = two_and_three_fail
    record_id = _queued_run(["Threat 1", "Threat 2", "Threat 3"])
    _write_batch(_on_last_try(record_id))
    stored = _scenarios_of(record_id)
    outage = AI_OUTAGE_MESSAGES[AiOutage.TIMED_OUT]
    assert stored[1]["failure"] == {
        "code": ErrorCode.UNAVAILABLE,
        "message": AI_PATH_OUTAGE_MESSAGE.format(outage=outage, tries=Lease.MAX_ATTEMPTS),
        "reason": AiOutage.TIMED_OUT,
    }
    assert "reason" not in stored[2]["failure"] and "did not answer" in stored[2]["failure"]["message"]


def test_with_no_path_written_an_outage_on_the_last_try_still_fails_the_job(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """Review fix 4: no evidence the provider works, so it is down: the job's own retry policy decides."""

    def provider_down(_: str) -> dict[str, Any]:
        raise Unavailable("down")

    chat.responders[AiTask.WRITE_SCENARIO] = provider_down
    record_id = _queued_run(["Threat 1", "Threat 2"])
    with pytest.raises(Unavailable):
        _write_batch(_on_last_try(record_id))
    assert _scenarios_of(record_id) == []


def test_a_last_try_that_fails_still_sends_the_saved_scenarios_controls_message(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """Review: the failure was raised before the controls message, and no retry follows a last try, so the
    saved scenario's controls waited for the sweep."""

    def threat_two_refused(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt:
            raise JobFailed(ErrorCode.AI_MISCONFIGURED, "key revoked")
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = threat_two_refused
    record_id = _queued_run(["Threat 1", "Threat 2"])
    with pytest.raises(JobFailed):
        _write_batch(_on_last_try(record_id))
    assert len(_scenarios_of(record_id)) == 1
    assert [task for task, _, _ in sent].count(TaskName.MAP_CONTROLS) == 2  # as it was saved, after the batch


def test_a_written_path_another_delivery_gave_up_on_ends_served(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """Review fix 8: a delivery that lost its lease saved the scenario after the new owner abandoned the path;
    the finish reconciles it, so the run ends complete with the path served."""
    record_id = _queued_run(["Threat 1"])
    _deliver_until_done(record_id)
    scenario_id = _scenarios_of(record_id)[0]["_id"]
    gave_up = {"plan.paths.0.served": None, "plan.paths.0.abandoned": True, "plan.paths.0.attempts": 5}
    again = {"status": Status.QUEUED, "active": True, "job.batch": [], "job.attempts": 0}
    _sessions().update_one({"_id": record_id}, {"$set": gave_up | again})
    assert _deliver_until_done(record_id) == 1
    run = _sessions().find_one({"_id": record_id})
    assert (run["plan"]["paths"][0]["served"], run["plan"]["paths"][0]["abandoned"]) == (scenario_id, False)
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE and run["counts"]["abandoned"] == 0


def test_an_answer_that_comes_back_after_its_run_was_cancelled_is_never_saved(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """G214 review: the AI answers seconds after the call; a scenario saved after a cancel had its controls
    wait again on the cancelled run (listed as work, the delete refused), or after a delete was left with no
    run. The job checks it still owns the run right before it saves."""
    record_id = _queued_run(["Threat 1"])

    def cancelled_meanwhile(user_prompt: str) -> dict[str, Any]:
        container.get_work_control_repository().cancel_scenario_session(record_id, 86, {"user_id": "u1"})
        return _answer_for(user_prompt)

    chat.responders[AiTask.WRITE_SCENARIO] = cancelled_meanwhile
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(LeaseLost):
        _write_batch(lease)
    assert _scenarios_of(record_id) == []


def test_each_saved_scenario_says_which_write_made_it_and_when(
    chat: FakeChatModel, sent: list[tuple[Any, ...]]
) -> None:
    """G267, v1's generation_epoch and gen_started_at / gen_finished_at: the write job's epoch, when the
    path's writing began and when its record was made; a failure card too."""
    written_id = _queued_run(["Threat 1", "Threat 2"])
    assert _deliver_until_done(written_id) == 1
    unsupported = _queued_run(["Threat on a removed system"], systems=(999,))
    _deliver_until_done(unsupported)
    for scenario in _scenarios_of(written_id) + _scenarios_of(unsupported):
        stamp = scenario["generation"]
        assert stamp["epoch"] == 1 and stamp["finished_at"] == scenario["created_at"]
        assert stamp["started_at"] is not None and stamp["started_at"] <= stamp["finished_at"]


def test_each_duplicate_check_reads_the_store_right_before_its_save_on_the_job_thread(
    chat: FakeChatModel, sent: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A scenario saved meanwhile is seen and two saves of one batch never race: the batch reads the held
    scenarios once before any AI call, then each save reads them itself, one after the other, on the job's
    thread."""
    scenarios = container.get_threat_scenario_repository()
    read = scenarios.list_scenarios_for_duplicate_check
    threads: list[int] = []

    def recorded(*args: Any) -> Any:
        threads.append(threading.get_ident())
        return read(*args)

    monkeypatch.setattr(scenarios, "list_scenarios_for_duplicate_check", recorded)
    record_id = _queued_run(["Threat 1", "Threat 2", "Threat 3", "Threat 4"])
    assert _deliver_until_done(record_id) == 1
    assert threads == [threading.get_ident()] * (1 + 4)


@pytest.mark.usefixtures("chat")
def test_a_run_deleted_after_its_claim_ends_as_stopped_by_its_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run deleted between the claim and the job's read is a normal stop, never logged as a failure."""
    record_id = _queued_run(["Threat 1"])
    monkeypatch.setitem(jobs.JOB_COLLECTIONS, Collection.SESSIONS, PUBLISHED.append)

    def deleted_then_written(lease: JobLease) -> None:
        _sessions().delete_one({"_id": record_id})
        _write_batch(lease)

    task = SimpleNamespace(name=TaskName.WRITE_SCENARIOS, request=SimpleNamespace(id="d1"))
    with capture_logs() as logs, pytest.raises(Ignore):
        jobs.run_leased_job(task, Collection.SESSIONS, record_id, 1, deleted_then_written)  # type: ignore[arg-type]
    events = [entry["event"] for entry in logs]
    assert LogEvent.JOB_STOPPED_BY_OWNER in events and LogEvent.JOB_FAILED not in events
