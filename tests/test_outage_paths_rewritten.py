"""A path the AI was too busy to write on the write job's last try keeps its card until the next set, or a
Regenerate on that card, writes it again; a path that keeps failing is still given up. Through the API and the
write job, on the test MongoDB with the write job's fake chat model."""

from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    AiTask,
    Collection,
    ConflictReason,
    ErrorCode,
    FindingCode,
    Generation,
    Lease,
    RunActionOutcome,
    ScenarioStatus,
    Status,
    Step,
    TargetProblem,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.domain.scenario.write import scenario_id
from tests.fakes import FakeChatModel
from tests.test_run_actions import (  # noqa: F401 - fixtures by name
    _deliver,
    _identity,
    _regenerate,
    _sessions,
    api_key,
    fake_chat,
    queued,
)
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _answer_for,
    _on_last_try,
    _queued_run,
    _scenarios_of,
    _write_batch,
    chat,
    sent,
    unreadable_then,
)


def _busy_for(threat_name: str) -> Callable[[str], dict[str, Any]]:
    """The writer's answers, with the AI service busy for `threat_name`: its first answer is unreadable and
    its rewrite (the set's second round, that path's alone) meets the outage."""
    return unreadable_then(threat_name, Unavailable(AI_OUTAGE_MESSAGES[AiOutage.BUSY], reason=AiOutage.BUSY))


def busy_for_and_blocked(busy_threat: str, blocked_threat: str) -> Callable[[str], dict[str, Any]]:
    """_busy_for(busy_threat), with `blocked_threat`'s scenario citing an advisory id: blocked in the set's
    first round, so given up at once, apart from the busy path's rewrite."""
    busy = _busy_for(busy_threat)

    def answer(user_prompt: str) -> dict[str, Any]:
        written = busy(user_prompt)
        if f'"{blocked_threat}"' in user_prompt:
            return written | {"scenario_statement": written["scenario_statement"] + " CVE-2024-1234 helps."}
        return written

    return answer


@pytest.mark.usefixtures("queued", "sent")
def test_a_path_the_ai_was_busy_for_on_the_last_try_is_written_by_the_next_set(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """The busy card's path stays open, not tried again by its own set; the next set replaces the card."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _sessions().update_one({"_id": record_id}, {"$set": {"step": Step.SCENARIOS}})
    _write_batch(_on_last_try(record_id))
    run, card = _sessions().find_one({"_id": record_id}), _scenarios_of(record_id)[1]
    assert (card["status"], card["failure"]["reason"]) == (ScenarioStatus.FAILED, AiOutage.BUSY)
    path = run["plan"]["paths"][1]
    assert (path["abandoned"], path["attempts"], run["counts"]["remaining"]) == (False, 1, 1)
    assert run["status"] == Status.DONE and "p2" not in run["job"]["set"]

    fake_chat.responders[AiTask.WRITE_SCENARIO] = _answer_for  # the outage has passed
    answer = client.post(f"/v1/sessions/{record_id}/scenarios/next-set", headers=_identity(api_key))
    assert answer.status_code == 202, answer.text
    assert [item["path_id"] for item in _sessions().find_one({"_id": record_id})["job"]["batch"]] == ["p2"]
    assert _deliver(record_id, 2) == 1
    run = _sessions().find_one({"_id": record_id})
    written = get_mongodb()[Collection.SCENARIOS].find_one({"_id": card["_id"]})
    assert written["status"] == ScenarioStatus.DONE and "failure" not in written
    assert run["plan"]["paths"][1]["served"] == card["_id"]
    assert (run["counts"]["written"], run["counts"]["failed"], run["counts"]["remaining"]) == (2, 0, 0)


@pytest.mark.usefixtures("sent")
def test_a_path_that_keeps_failing_is_still_given_up(fake_chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """An outage counts an attempt, so MAX_PATH_ATTEMPTS ends it; any other failure is given up at once."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = busy_for_and_blocked("Threat 2", "Blocked threat")
    record_id = _queued_run(["Threat 1", "Threat 2", "Blocked threat"])
    tried = {"plan.paths.1.attempts": Generation.MAX_PATH_ATTEMPTS - 1}
    _sessions().update_one({"_id": record_id}, {"$set": tried})
    _write_batch(_on_last_try(record_id))
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert [path["abandoned"] for path in paths] == [False, True, True]
    assert [path["attempts"] for path in paths[1:]] == [Generation.MAX_PATH_ATTEMPTS, 1]


def _run_with_a_busy_card(threat_names: list[str], limit: int = 0, attempts: int = 0) -> tuple[str, str]:
    """A done run whose path p2 the AI was busy for on the write job's last try, after `attempts` earlier
    tries (a spare that took its place written too): the run's id and p2's failure card's id."""
    record_id = _queued_run(threat_names, limit=limit)
    changes = {"step": Step.SCENARIOS, "plan.paths.1.attempts": attempts}
    _sessions().update_one({"_id": record_id}, {"$set": changes})
    _write_batch(_on_last_try(record_id))
    _deliver(record_id, 1)
    card = _scenarios_of(record_id)[1]
    assert (card["status"], card["failure"]["reason"]) == (ScenarioStatus.FAILED, AiOutage.BUSY)
    return record_id, card["_id"]


def _regen_summary(outcome: RunActionOutcome, replaced: int, epoch: int = 2) -> dict[str, Any]:
    """The run's last_regen for one target."""
    return {"outcome": outcome, "requested": 1, "replaced": replaced, "epoch": epoch}


@pytest.mark.usefixtures("queued")
def test_regenerate_writes_a_busy_card_again_in_place(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
    sent: list[tuple[Any, ...]],  # noqa: F811 - the imported fixture
) -> None:
    """Owner: Regenerate on the card writes its path's first scenario again under the card's id (version 1),
    as the next set does; its controls are mapped and no path is left to write."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    record_id, card = _run_with_a_busy_card(["Threat 1", "Threat 2"])
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _answer_for  # the outage has passed
    answer = _regenerate(client, api_key, record_id, [card])
    assert answer.status_code == 202, answer.text
    assert _sessions().find_one({"_id": record_id})["job"]["batch"] == [{"path_id": "p2", "replaces": None}]
    sent.clear()
    assert _deliver(record_id, 2) == 1
    written = _scenarios_of(record_id)
    assert (written[1]["_id"], written[1]["status"], written[1]["version"]) == (card, ScenarioStatus.DONE, 1)
    assert "failure" not in written[1] and len(written) == 2
    run = _sessions().find_one({"_id": record_id})
    assert (run["status"], run["plan"]["paths"][1]["served"]) == (Status.DONE, card)
    assert (run["counts"]["written"], run["counts"]["failed"], run["counts"]["remaining"]) == (2, 0, 0)
    assert run["last_regen"] == _regen_summary(RunActionOutcome.COMPLETE, 1)
    assert (TaskName.MAP_CONTROLS, record_id, 2) in sent
    again = client.post(f"/v1/sessions/{record_id}/scenarios/next-set", headers=_identity(api_key))
    assert (again.status_code, again.json()["reason"]) == (409, ConflictReason.NOTHING_LEFT)


@pytest.mark.usefixtures("queued", "sent")
def test_an_outage_again_on_the_last_try_keeps_the_card_and_ends_the_run_done(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """The card stays failed with its reason and its path open; the regenerate ends partial, never failed."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    record_id, card = _run_with_a_busy_card(["Threat 1", "Threat 2"])
    assert _regenerate(client, api_key, record_id, [card]).status_code == 202
    _sessions().update_one({"_id": record_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    assert _deliver(record_id, 2) == 1
    failed = _scenarios_of(record_id)[1]
    assert (failed["_id"], failed["status"], failed["failure"]["reason"]) == (
        card,
        ScenarioStatus.FAILED,
        AiOutage.BUSY,
    )
    run = _sessions().find_one({"_id": record_id})
    path = run["plan"]["paths"][1]
    assert (path["abandoned"], path["attempts"], path["served"]) == (False, 2, None)
    assert run["status"] == Status.DONE and run["last_regen"] == _regen_summary(RunActionOutcome.PARTIAL, 0)


@pytest.mark.usefixtures("queued", "sent")
def test_regenerate_writes_again_a_path_given_up_after_its_last_attempt(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """Owner: a busy card's path given up after MAX_PATH_ATTEMPTS (a spare took its place) is opened again;
    an outage again gives it up again and pulls no spare; once written, the run is one over its target."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    threats, tries = ["Threat 1", "Threat 2", "Threat 3", "Threat 4"], Generation.MAX_PATH_ATTEMPTS
    record_id, card = _run_with_a_busy_card(threats, limit=2, attempts=tries - 1)
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert (paths[1]["abandoned"], paths[1]["replaced_by"], paths[3]["selected"]) == (True, "p3", False)
    assert _regenerate(client, api_key, record_id, [card]).status_code == 202
    _sessions().update_one({"_id": record_id}, {"$set": {"job.attempts": Lease.MAX_ATTEMPTS - 1}})
    assert _deliver(record_id, 2) == 1
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert (paths[1]["abandoned"], paths[1]["attempts"], paths[3]["selected"]) == (True, tries + 1, False)
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _answer_for
    assert _regenerate(client, api_key, record_id, [card]).status_code == 202
    assert _deliver(record_id, 3) == 1
    run = _sessions().find_one({"_id": record_id})
    paths = run["plan"]["paths"]
    assert (paths[1]["served"], paths[1]["abandoned"], paths[3]["selected"]) == (card, False, False)
    assert (run["counts"]["written"], run["counts"]["abandoned"], run["plan"]["target"]) == (3, 0, 2)
    assert run["last_regen"] == _regen_summary(RunActionOutcome.COMPLETE, 1, epoch=3)


@pytest.mark.usefixtures("queued", "sent")
def test_one_regenerate_writes_a_new_version_and_a_busy_card_again(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """A written scenario gets its version 2 and the busy card is written in place, in one job."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    record_id, card = _run_with_a_busy_card(["Threat 1", "Threat 2"])
    first, second = scenario_id(record_id, "p1", 1), scenario_id(record_id, "p1", 2)
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _answer_for
    assert _regenerate(client, api_key, record_id, [first, card]).status_code == 202
    batch = _sessions().find_one({"_id": record_id})["job"]["batch"]
    assert batch == [{"path_id": "p1", "replaces": first}, {"path_id": "p2", "replaces": None}]
    assert _deliver(record_id, 2) == 1
    scenarios = get_mongodb()[Collection.SCENARIOS]
    assert scenarios.find_one({"_id": first})["superseded_by"] == second
    assert scenarios.find_one({"_id": second})["replaces"] == first
    assert scenarios.find_one({"_id": card})["status"] == ScenarioStatus.DONE
    run = _sessions().find_one({"_id": record_id})
    assert {path["path_id"]: path["served"] for path in run["plan"]["paths"]} == {"p1": second, "p2": card}
    assert run["last_regen"] == _regen_summary(RunActionOutcome.COMPLETE, 2) | {"requested": 2}


@pytest.mark.usefixtures("queued", "sent")
def test_a_regenerate_gives_up_a_card_path_that_repeats_a_held_scenario_but_never_a_version(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """The busy card's path now repeats p1's scenario: given up with no AI call, as the next set would, and
    the card says so, so it is not regenerated again. p1 repeats p3's, yet a version is never given up: it is
    written, then kept hidden as a near copy."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    record_id, card = _run_with_a_busy_card(["Threat 1", "Threat 2", "Threat 3"])
    scenarios, first = get_mongodb()[Collection.SCENARIOS], scenario_id(record_id, "p1", 1)
    third = scenario_id(record_id, "p3", 1)
    threat = {sid: scenarios.find_one({"_id": sid})["content"]["threat"] for sid in (first, card)}
    scenarios.update_one({"_id": first}, {"$set": {"content.threat": threat[card]}})
    scenarios.update_one({"_id": third}, {"$set": {"content.threat": threat[first]}})
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _answer_for
    calls_before = len(fake_chat.calls)
    assert _regenerate(client, api_key, record_id, [first, card]).status_code == 202
    assert _deliver(record_id, 2) == 1
    briefs = [prompt for task, prompt in fake_chat.calls[calls_before:] if task == AiTask.WRITE_SCENARIO]
    assert briefs and not any('"Threat 2"' in brief for brief in briefs)
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert (paths[0]["abandoned"], paths[1]["abandoned"], paths[1]["repeats"]) == (False, True, first)
    given_up = scenarios.find_one({"_id": card})
    failure = given_up["failure"]
    assert (given_up["status"], failure["code"]) == (ScenarioStatus.FAILED, FindingCode.NEAR_DUPLICATE)
    assert "reason" not in failure and first in failure["message"]
    assert scenarios.find_one({"_id": first})["regenerate_error"]["code"] == ErrorCode.SCENARIO_BLOCKED
    again = _regenerate(client, api_key, record_id, [card])
    assert again.json()["errors"] == [{"scenario_id": card, "reason": TargetProblem.FAILURE_SCENARIO}]


@pytest.mark.usefixtures("queued", "sent")
def test_regenerate_serves_a_given_up_path_whose_card_an_earlier_delivery_wrote(
    client: TestClient,
    api_key: str,  # noqa: F811 - the imported fixture
    fake_chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """A delivery saved the card's scenario, then died before its path's write: the next one serves the path
    with no AI call, and the path is no longer given up."""
    fake_chat.responders[AiTask.WRITE_SCENARIO] = _busy_for("Threat 2")
    threats, tries = ["Threat 1", "Threat 2", "Threat 3", "Threat 4"], Generation.MAX_PATH_ATTEMPTS
    record_id, card = _run_with_a_busy_card(threats, limit=2, attempts=tries - 1)
    assert _regenerate(client, api_key, record_id, [card]).status_code == 202
    written = {"$set": {"status": ScenarioStatus.DONE}, "$unset": {"failure": ""}}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": card}, written)
    calls_before = len(fake_chat.calls)
    assert _deliver(record_id, 2) == 1
    assert not [task for task, _ in fake_chat.calls[calls_before:] if task == AiTask.WRITE_SCENARIO]
    run = _sessions().find_one({"_id": record_id})
    assert (run["plan"]["paths"][1]["served"], run["plan"]["paths"][1]["abandoned"]) == (card, False)
    assert run["counts"]["abandoned"] == 0
    assert run["last_regen"] == _regen_summary(RunActionOutcome.COMPLETE, 1)
