"""Giving a finished run more work (Step 14, BUILD_PLAN S40-S41): next set (#7) and regenerate (#6),
through the API and then the write job, on the test MongoDB with the write job's fake chat model and
fixtures (tests/test_writing_job)."""

import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ConflictReason,
    Decision,
    ErrorCode,
    Header,
    RunActionKind,
    RunActionOutcome,
    ScenarioStatus,
    Status,
    Step,
    TargetProblem,
    TaskName,
)
from app.core.database import get_mongodb
from app.data_access.job_control import JobControlRecords
from app.data_access.job_records import JobLease, LeaseLost
from app.data_access.run_actions import RunActionRecords
from app.engine.scenarios.review_checks import why_ids_cannot_be_regenerated
from app.engine.scenarios.writing.brief_builder import _newest_within
from app.engine.scenarios.writing.scenario_record import scenario_id
from app.models.api_clients import Principal
from app.models.scenarios import SessionStatus
from app.services.api_clients import get_api_client_service
from app.services.scenarios import run_actions as run_actions_module
from app.services.scenarios.run_actions import get_run_actions
from app.worker.tasks import writing
from tests.test_writing_job import _answer_for, _queued_run, chat, sent  # noqa: F401 — fixtures by name

THREATS = [f"Threat {number}" for number in range(1, 9)]  # 8 paths: a batch of 6, then 2


@pytest.fixture(scope="module")
def api_key() -> str:
    _, key = get_api_client_service().mint_api_client(f"actions-{uuid.uuid4().hex[:8]}", None, "test")
    return key


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[tuple[Any, ...]]]:
    """The jobs the API sends."""
    messages: list[tuple[Any, ...]] = []
    monkeypatch.setattr(run_actions_module, "send_job", lambda *args: messages.append(args))
    monkeypatch.setattr(run_actions_module, "publish_session_status", lambda session_id: None)
    yield messages


@pytest.fixture
def fake_chat(request: pytest.FixtureRequest) -> Any:
    """The write job's fake chat model (its `chat` fixture), by a name that does not shadow the import."""
    return request.getfixturevalue("chat")


def _identity(api_key: str, entity_id: int = 86) -> dict[str, str]:
    return {
        Header.API_KEY: api_key,
        Header.USER_ID: "u1",
        Header.ENTITY_ID: str(entity_id),
        Header.TENANT_ID: "DESC",
    }


def _sessions() -> Any:
    return get_mongodb()[Collection.SESSIONS]


def _deliver(record_id: str, epoch: int) -> int:
    """Each message the write job sends itself, delivered in turn until the run ends: how many deliveries."""
    deliveries = 0
    while (
        lease := JobLease.claim(
            _sessions(), record_id, epoch, TaskName.WRITE_SCENARIOS, f"{epoch}-{deliveries}"
        )
    ) is not None:
        deliveries += 1
        writing.write_batch(lease)
    return deliveries


def _interrupted_run() -> str:
    """A run whose first batch was written, then its job failed (an outage on its last try): 2 paths open."""
    record_id = _queued_run(THREATS)
    lease = JobLease.claim(_sessions(), record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    assert lease is not None
    writing.write_batch(lease)  # writes 6 and hands the last 2 to itself
    _sessions().update_one(
        {"_id": record_id},
        {"$set": {"status": Status.FAILED, "active": False, "step": Step.SCENARIOS,
                  "job.error": {"code": "unavailable", "message": "down"}}},
    )  # fmt: skip
    return record_id


@pytest.mark.usefixtures("chat", "sent")
def test_next_set_resumes_an_interrupted_run_and_the_job_writes_the_rest(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]]
) -> None:
    """T-SCN-20: 202 {epoch 2}; the run queued again with its open paths only and its old error cleared; the
    write job then ends it complete; one audit record."""
    record_id = _interrupted_run()
    three_days_ago = datetime.now(UTC) - timedelta(days=3)  # the reviewer came back days after the plan
    _sessions().update_one({"_id": record_id}, {"$set": {"plan.frozen_at": three_days_ago}})
    answer = client.post(f"/v1/sessions/{record_id}/scenarios/next-set", headers=_identity(api_key))
    assert (answer.status_code, answer.json()) == (202, {"epoch": 2}), answer.text
    assert queued == [(TaskName.WRITE_SCENARIOS, record_id, 2)]
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["active"], run["job"]["error"]) == (Status.QUEUED, True, None)
    assert [item["path_id"] for item in run["job"]["batch"]] == ["p7", "p8"]
    assert run["last_action"]["kind"] == RunActionKind.NEXT_SET
    # Shown from the moment it is asked, so the status never shows the set before (review 2026-10-12).
    assert run["last_next_set"] == {"outcome": RunActionOutcome.RUNNING, "requested": 2, "delivered": None}
    assert _deliver(record_id, 2) == 1
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["last_action"]["outcome"]) == (Status.DONE, RunActionOutcome.COMPLETE)
    assert run["counts"]["written"] == 8
    # Review 2026-10-11: the next set's own writing time, never the three days since the plan.
    assert run["timings"]["scenarios_s"] < 60
    # What the status shows of it (owner 2026-10-12): the set asked for and what it delivered.
    assert run["last_next_set"] == {"outcome": RunActionOutcome.COMPLETE, "requested": 2, "delivered": 2}
    progress = client.get(f"/v1/sessions/{record_id}", headers=_identity(api_key)).json()["progress"]
    assert progress["last_next_set"] == run["last_next_set"] and progress["last_regen"] is None
    assert progress["timings"]["scenarios"] == run["timings"]["scenarios_s"]
    audit = {"target.id": record_id, "action": AuditAction.RUN_NEXT_SET}
    assert get_mongodb()[Collection.AUDIT].count_documents(audit) == 1


@pytest.mark.usefixtures("chat", "sent")
def test_next_set_twice_or_at_once_queues_one_job(
    client: TestClient,
    api_key: str,
    queued: list[tuple[Any, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """T-SCN-21/22: a second click finds the run queued (409 generation_in_progress); two clicks at the same
    moment both read epoch 1, and the conditional update lets exactly one through."""
    record_id = _interrupted_run()
    url = f"/v1/sessions/{record_id}/scenarios/next-set"
    assert client.post(url, headers=_identity(api_key)).status_code == 202
    again = client.post(url, headers=_identity(api_key))
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)

    record_id = _interrupted_run()
    run = SessionStatus.from_record(_sessions().find_one({"_id": record_id}))
    barrier, read = threading.Barrier(2), RunActionRecords.find_for_action

    def read_then_wait(self: RunActionRecords, session_id: str, with_paths: bool) -> dict[str, Any]:
        found = read(self, session_id, with_paths)
        barrier.wait(timeout=10)
        return found

    monkeypatch.setattr(RunActionRecords, "find_for_action", read_then_wait)
    actions, principal, outcomes = get_run_actions(), Principal("client", "u1", 86, "DESC"), []

    def click() -> None:
        try:
            outcomes.append(actions.next_set(principal, run).epoch)
        except Exception as error:  # noqa: BLE001 — the test counts what each click got
            outcomes.append(getattr(error, "reason", error))

    threads = [threading.Thread(target=click) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(map(str, outcomes)) == sorted(["2", ConflictReason.GENERATION_IN_PROGRESS])


@pytest.mark.usefixtures("chat", "sent")
def test_each_next_set_writes_its_size_in_waves_then_stops_until_asked_again(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G196 (owner 2026-10-11, as v1): with NEXT_SET_SIZE 8 a next set asks for the next 8 paths by rank;
    the write job writes them in two waves (6 + 2), handing the set on to itself, and stops; the next call
    asks for the last 4, and one more finds nothing left."""
    monkeypatch.setattr(get_settings(), "next_set_size", 8)
    record_id = _queued_run([f"Threat {number}" for number in range(1, 15)], first_set=2)
    _sessions().update_one({"_id": record_id}, {"$set": {"step": Step.SCENARIOS}})
    assert _deliver(record_id, 1) == 1
    url = f"/v1/sessions/{record_id}/scenarios/next-set"
    assert client.post(url, headers=_identity(api_key)).status_code == 202
    run = _sessions().find_one({"_id": record_id})
    assert run["job"]["set"] == [f"p{number}" for number in range(3, 11)]
    assert len(run["job"]["batch"]) == 6
    assert _deliver(record_id, 2) == 2
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["counts"]["written"], run["counts"]["remaining"]) == (Status.DONE, 10, 4)
    assert client.post(url, headers=_identity(api_key)).status_code == 202
    assert _deliver(record_id, 3) == 1
    assert _sessions().find_one({"_id": record_id})["counts"]["written"] == 14
    nothing = client.post(url, headers=_identity(api_key))
    assert (nothing.status_code, nothing.json()["reason"]) == (409, ConflictReason.NOTHING_LEFT)
    audit = {"target.id": record_id, "action": AuditAction.RUN_NEXT_SET}
    asked = sorted(record["after"]["set"][0] for record in get_mongodb()[Collection.AUDIT].find(audit))
    assert asked == ["p11", "p3"]  # each next set audited with the paths it asked for


@pytest.mark.usefixtures("chat", "sent")
def test_a_path_an_interruption_left_is_written_within_the_next_set_never_on_top(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], monkeypatch: pytest.MonkeyPatch
) -> None:
    """G196 (as v1: "next set -> p3 (failed) + p7"): the run failed with p7 and p8 unwritten; a next set of 1
    writes p7, the best-ranked of them, and only p7."""
    monkeypatch.setattr(get_settings(), "next_set_size", 1)
    record_id = _interrupted_run()
    url = f"/v1/sessions/{record_id}/scenarios/next-set"
    assert client.post(url, headers=_identity(api_key)).status_code == 202
    assert _deliver(record_id, 2) == 1
    paths = {path["path_id"]: path for path in _sessions().find_one({"_id": record_id})["plan"]["paths"]}
    assert paths["p7"]["served"] and not paths["p8"]["served"]


def test_next_set_names_why_nothing_is_left(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]]
) -> None:
    """T-SCN-23: every selected path written → nothing_left; some left out by the scenario count →
    target_reached; some set aside after repeated failures → scenarios_abandoned; nothing is queued."""
    written = {"selected": True, "served": "s", "abandoned": False, "attempts": 0, "rank": 1, "path_id": "a"}
    for paths, reason in (
        ([written], ConflictReason.NOTHING_LEFT),
        ([written, written | {"selected": False, "served": None}], ConflictReason.TARGET_REACHED),
        ([written, written | {"served": None, "abandoned": True}], ConflictReason.SCENARIOS_ABANDONED),
    ):
        record_id = uuid.uuid4().hex
        _sessions().insert_one(
            {"_id": record_id, "entity_id": 86, "asset_id": 2, "status": Status.DONE, "step": Step.SCENARIOS,
             "job": {"epoch": 1}, "plan": {"paths": paths}, "updated_at": datetime.now(UTC)}
        )  # fmt: skip
        answer = client.post(f"/v1/sessions/{record_id}/scenarios/next-set", headers=_identity(api_key))
        assert (answer.status_code, answer.json()["reason"]) == (409, reason)
    assert queued == []


@pytest.mark.usefixtures("chat", "sent")
def test_next_set_while_another_run_holds_the_asset_and_for_another_entity(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]]
) -> None:
    """asset_busy (one active run per asset) names the active run, and the run stays as it was; another
    entity's run → 403."""
    record_id = _interrupted_run()
    asset_id = _sessions().find_one({"_id": record_id})["asset_id"]
    other = uuid.uuid4().hex
    _sessions().insert_one(
        {"_id": other, "entity_id": 86, "asset_id": asset_id, "active": True, "status": Status.RUNNING}
    )
    url = f"/v1/sessions/{record_id}/scenarios/next-set"
    busy = client.post(url, headers=_identity(api_key))
    assert (busy.status_code, busy.json()["reason"]) == (409, ConflictReason.ASSET_BUSY)
    assert busy.json()["details"] == {"active_session_id": other}
    assert _sessions().find_one({"_id": record_id})["status"] == Status.FAILED
    assert client.post(url, headers=_identity(api_key, 87)).status_code == 403
    assert queued == []


def _scenarios() -> Any:
    return get_mongodb()[Collection.SCENARIOS]


def _written_run(threat_names: list[str]) -> str:
    """A run written to the end (status done, step scenarios as the planner leaves it), every path served by
    version 1."""
    record_id = _queued_run(threat_names)
    _sessions().update_one({"_id": record_id}, {"$set": {"step": Step.SCENARIOS}})
    _deliver(record_id, 1)
    return record_id


def _regenerate(client: TestClient, api_key: str, record_id: str, scenario_ids: list[str]) -> Any:
    url = f"/v1/sessions/{record_id}/regenerate/scenarios"
    return client.post(url, json={"scenario_ids": scenario_ids}, headers=_identity(api_key))


@pytest.mark.usefixtures("sent")
def test_regenerate_writes_the_next_version_and_an_accepted_one_stays_accepted(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], fake_chat: Any
) -> None:
    """T-SCN-24: 202 {epoch 2}; the job writes version 2 (pending, `replaces` v1, told to differ from v1),
    then supersedes v1, which stays accepted; the path is served by v2; the run ends complete."""
    record_id = _written_run(["Threat 1", "Threat 2"])
    first = scenario_id(record_id, "p1", 1)
    _scenarios().update_one({"_id": first}, {"$set": {"decision": Decision.ACCEPTED}})
    answer = _regenerate(client, api_key, record_id, [first])
    assert (answer.status_code, answer.json()) == (202, {"epoch": 2}), answer.text
    assert _sessions().find_one({"_id": record_id})["job"]["batch"] == [{"path_id": "p1", "replaces": first}]
    calls_before = len(fake_chat.calls)
    assert _deliver(record_id, 2) == 1
    second = _scenarios().find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert (second["version"], second["replaces"], second["decision"]) == (2, first, Decision.PENDING)
    old = _scenarios().find_one({"_id": first})
    assert (old["superseded_by"], old["decision"]) == (second["_id"], Decision.ACCEPTED)
    briefs = [prompt for task, prompt in fake_chat.calls[calls_before:] if task == AiTask.WRITE_SCENARIO]
    assert briefs and '"other_scenarios"' in briefs[0] and old["content"]["statement"] in briefs[0]
    run = _sessions().find_one({"_id": record_id})
    served = {path["path_id"]: path["served"] for path in run["plan"]["paths"]}
    assert served["p1"] == second["_id"]
    assert (run["last_action"]["kind"], run["last_action"]["outcome"]) == (
        RunActionKind.REGENERATE,
        RunActionOutcome.COMPLETE,
    )
    assert (run["status"], run["active"], run["counts"]["written"]) == (Status.DONE, False, 2)
    assert run["last_regen"] == {"outcome": RunActionOutcome.COMPLETE, "requested": 1, "replaced": 1}
    assert run["timings"]["scenarios_s"] < 60 and "last_next_set" not in run
    again = _regenerate(client, api_key, record_id, [first])
    assert again.json()["errors"] == [{"scenario_id": first, "reason": TargetProblem.VERSION_NOT_CURRENT}]


@pytest.mark.usefixtures("sent")
def test_a_failed_regenerate_keeps_the_version_current_with_its_reason(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], fake_chat: Any
) -> None:
    """T-SCN-25 (R-8): unreadable twice → no new version; v1 stays current with regenerate_error; the path's
    attempts do not change; the run ends partial. A later successful regenerate clears the reason."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)
    writes = fake_chat.responders[AiTask.WRITE_SCENARIO]
    fake_chat.responders[AiTask.WRITE_SCENARIO] = lambda prompt: {"scenario_title": "x"}
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202
    _deliver(record_id, 2)
    old = _scenarios().find_one({"_id": first})
    assert old["superseded_by"] is None and old["regenerate_error"]["code"] == ErrorCode.GENERATION_FAILED
    assert _scenarios().count_documents({"session_id": record_id}) == 1
    run = _sessions().find_one({"_id": record_id})
    assert run["plan"]["paths"][0]["attempts"] == 0
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL
    assert run["last_regen"] == {"outcome": RunActionOutcome.PARTIAL, "requested": 1, "replaced": 0}
    fake_chat.responders[AiTask.WRITE_SCENARIO] = writes
    assert _regenerate(client, api_key, record_id, [first]).json() == {"epoch": 3}
    _deliver(record_id, 3)
    assert "regenerate_error" not in _scenarios().find_one({"_id": first})


@pytest.mark.usefixtures("sent")
def test_a_crash_between_the_two_writes_is_healed_without_an_ai_call(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], fake_chat: Any
) -> None:
    """T-SCN-26 (R-8): version 2 saved, version 1 not yet superseded when the worker died: the retry only
    supersedes v1 and serves v2."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202
    saved = _scenarios().find_one({"_id": first}) | {"_id": scenario_id(record_id, "p1", 2), "version": 2}
    _scenarios().insert_one(saved | {"replaces": first, "title_key": "another title"})
    calls_before = len(fake_chat.calls)
    _deliver(record_id, 2)
    assert len(fake_chat.calls) == calls_before
    assert _scenarios().find_one({"_id": first})["superseded_by"] == saved["_id"]
    run = _sessions().find_one({"_id": record_id})
    assert run["plan"]["paths"][0]["served"] == saved["_id"]
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE


@pytest.mark.usefixtures("chat", "sent")
def test_regenerate_names_every_id_it_cannot_take(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]]
) -> None:
    """T-SCN-27: unknown, a failure card (the write job retries it), an older version → one 409 with every
    id; nothing queued; while a job runs → 409 generation_in_progress."""
    record_id = _written_run(["Threat 1", "Threat 2"])
    first, second = scenario_id(record_id, "p1", 1), scenario_id(record_id, "p2", 1)
    newer = _scenarios().find_one({"_id": second}) | {"_id": "newer", "version": 2, "title_key": "newer"}
    _scenarios().update_one({"_id": second}, {"$set": {"superseded_by": "newer"}})
    _scenarios().insert_one(newer)
    card = _scenarios().find_one({"_id": first}) | {"_id": "card", "path_id": "p3"}
    _scenarios().insert_one(card | {"status": ScenarioStatus.FAILED, "title_key": "card"})
    answer = _regenerate(client, api_key, record_id, ["missing", "card", second])
    assert (answer.status_code, answer.json()["reason"]) == (409, ConflictReason.SCENARIOS_NOT_REGENERABLE)
    assert {error["scenario_id"]: error["reason"] for error in answer.json()["errors"]} == {
        "missing": TargetProblem.UNKNOWN,
        "card": TargetProblem.FAILURE_SCENARIO,
        second: TargetProblem.VERSION_NOT_CURRENT,
    }
    assert queued == []
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202
    busy = _regenerate(client, api_key, record_id, ["newer"])
    assert (busy.status_code, busy.json()["reason"]) == (409, ConflictReason.GENERATION_IN_PROGRESS)


def test_regenerate_refuses_two_versions_of_one_path() -> None:
    """T-SCN-27: two current versions of one path in one call (possible only while a crash is unhealed)."""
    targets = {
        "v1": {"path_id": "p1", "status": ScenarioStatus.DONE, "superseded_by": None},
        "v2": {"path_id": "p1", "status": ScenarioStatus.DONE, "superseded_by": None},
    }
    errors = why_ids_cannot_be_regenerated(["v1", "v2"], targets)
    assert [error["reason"] for error in errors] == [TargetProblem.DUPLICATE_VERSION] * 2


def test_the_writer_sees_the_newest_versions_that_fit() -> None:
    """S41 review: a path regenerated many times never pushes the prompt past the model input; the newest
    versions are kept, oldest first."""
    assert _newest_within(("a" * 10, "b" * 10, "c" * 10), 25) == ("b" * 10, "c" * 10)
    assert _newest_within(("a" * 30,), 25) == ()


def test_a_failed_job_never_leaves_the_run_reading_running() -> None:
    """G141 (S43 review): the job's own failure and both of the reaper's end `last_action` too, so a run (or a
    next set or regenerate) that failed no longer says `running` beside status `failed`."""
    from datetime import timedelta

    from app.core.constants import ErrorCode
    from app.data_access.job_records import JobRecords

    def queued_run() -> str:
        record_id = uuid.uuid4().hex
        _sessions().insert_one(
            {"_id": record_id, "status": Status.QUEUED, "updated_at": datetime.now(UTC),
             "last_action": {"kind": RunActionKind.NEXT_SET, "outcome": RunActionOutcome.RUNNING},
             "job": {"task": TaskName.WRITE_SCENARIOS, "epoch": 2, "due_at": datetime.now(UTC)}}
        )  # fmt: skip
        return record_id

    error = {"code": ErrorCode.UNAVAILABLE, "message": "down"}
    own = queued_run()
    lease = JobLease.claim(_sessions(), own, 2, TaskName.WRITE_SCENARIOS, "t1")
    assert lease is not None and lease.fail(ErrorCode.UNAVAILABLE, "down")
    records, later = JobRecords(_sessions()), datetime.now(UTC) + timedelta(hours=1)
    expired = queued_run()
    assert JobLease.claim(_sessions(), expired, 2, TaskName.WRITE_SCENARIOS, "t2") is not None
    assert records.fail_expired(_sessions().find_one({"_id": expired}, {"job": 1}), error, later)
    unsent = queued_run()
    assert records.fail_unsent(_sessions().find_one({"_id": unsent}, {"job": 1}), error, later)
    for record_id in (own, expired, unsent):
        run = _sessions().find_one({"_id": record_id})
        assert (run["status"], run["last_action"]["outcome"]) == (Status.FAILED, RunActionOutcome.FAILED)
        assert run["last_action"]["kind"] == RunActionKind.NEXT_SET


@pytest.fixture
def job_messages(request: pytest.FixtureRequest) -> Any:
    """The messages the write job sends (its `sent` fixture), by a name that does not shadow the import."""
    return request.getfixturevalue("sent")


@pytest.mark.usefixtures("chat")
def test_a_crash_after_superseding_is_healed_whole(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], job_messages: list[tuple[Any, ...]]
) -> None:
    """G147: version 2 saved and version 1 superseded, then the worker died before the path's fenced write:
    the retry serves the path by v2, refreshes the counts and sends the controls message, with no AI call."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202
    second = scenario_id(record_id, "p1", 2)
    saved = _scenarios().find_one({"_id": first}) | {"_id": second, "version": 2, "title_key": "v2"}
    _scenarios().insert_one(saved | {"replaces": first, "controls": {"status": Status.QUEUED}})
    _scenarios().update_one({"_id": first}, {"$set": {"superseded_by": second}})
    job_messages.clear()
    _deliver(record_id, 2)
    run = _sessions().find_one({"_id": record_id})
    assert run["plan"]["paths"][0]["served"] == second
    assert run["counts"]["controls_waiting"] == 1
    assert (TaskName.MAP_CONTROLS, record_id, 2) in job_messages


@pytest.mark.usefixtures("sent")
def test_a_new_version_that_comes_back_after_its_run_was_cancelled_is_never_saved(
    client: TestClient, api_key: str, queued: list[tuple[Any, ...]], fake_chat: Any
) -> None:
    """G214 review: as for the first writing, a regenerate checks it still owns the run before it saves."""
    record_id = _written_run(["Threat 1"])
    first = scenario_id(record_id, "p1", 1)
    assert _regenerate(client, api_key, record_id, [first]).status_code == 202

    def cancelled_meanwhile(user_prompt: str) -> dict[str, Any]:
        JobControlRecords(get_mongodb()).cancel_run(record_id, 86, {"user_id": "u1"})
        return _answer_for(user_prompt)

    fake_chat.responders[AiTask.WRITE_SCENARIO] = cancelled_meanwhile
    with pytest.raises(LeaseLost):
        _deliver(record_id, 2)
    assert _scenarios().find_one({"_id": scenario_id(record_id, "p1", 2)}) is None
    assert _scenarios().find_one({"_id": first})["superseded_by"] is None
