"""G229 in the write job (owner 2026-10-13: "Reject the invalid candidate and follow the bounded replacement
policy ... final_scenario_count <= TOTAL_SCENARIO_COUNT"). A path whose scenario is blocked (here by the
reviewer's mismatch or as a duplicate) is given up at once; with TOTAL_SCENARIO_COUNT N a reserve takes its
place in the same set, the selected count never grows; with 0 a later set's open path does, and with none left
nothing is padded. A path repeating a held scenario is given up before any AI call. The job runs on the test
MongoDB with the fake chat model."""

from typing import Any

import pytest

from app.core.constants import (
    AiTask,
    Collection,
    ConflictReason,
    Decision,
    FindingCode,
    FindingMessage,
    Generation,
    RunActionOutcome,
    ScenarioStatus,
    UnselectedReason,
)
from app.core.database import get_mongodb
from tests.fakes import FakeChatModel
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _answer_for,
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

pytestmark = pytest.mark.usefixtures("sent")

_MISMATCH = FindingMessage.SCENARIO_MISMATCH.format(parts="threat")


def _mismatched_for_threats_named(fake: FakeChatModel, prefix: str) -> None:
    """The fake reviewer, finding another threat told for the threats named `prefix`..."""
    fake.responders[AiTask.PLAN_CHECK] = lambda prompt: {
        "rules": {"1": "holds"}, "same_threat": f'"threat": "{prefix}' not in prompt, "same_impact": True,
    }  # fmt: skip


def _plan(record_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    run = _sessions().find_one({"_id": record_id})
    return run, {path["path_id"]: path for path in run["plan"]["paths"]}


def _on_the_asset_of(record_id: str, earlier: str) -> None:
    """Run `record_id` on the asset of run `earlier` (done by now, so the asset is free)."""
    asset_id = _sessions().find_one({"_id": earlier})["asset_id"]
    _sessions().update_one({"_id": record_id}, {"$set": {"asset_id": asset_id}})


def test_a_rejected_path_is_replaced_by_a_reserve_and_the_limit_holds(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3", "Threat 4"], limit=2)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    failed, reserve = paths["p1"], paths["p3"]
    assert (failed["selected"], failed["abandoned"]) == (False, True)
    assert failed["attempts"] == 1  # given up at once, never written again
    assert (failed["abandoned_reason"], failed["replaced_by"]) == (FindingCode.SCENARIO_MISMATCH, "p3")
    assert reserve["selected"] and reserve["replaces"] == "p1" and reserve["served"]
    assert not paths["p4"]["selected"] and sum(path["selected"] for path in paths.values()) == 2
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 3  # p1, p2, p3
    done = [s for s in _scenarios_of(record_id) if s["status"] == ScenarioStatus.DONE]
    assert sorted(s["path_id"] for s in done) == ["p2", "p3"]
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE and run["counts"]["replaced"] == 1


def test_with_no_limit_and_every_path_in_the_set_a_rejected_path_is_not_replaced(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """No reserve and no later set's path: nothing is padded, the set ends partial."""
    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3"])
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert paths["p1"]["abandoned"] and paths["p1"].get("replaced_by") is None
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 3 and len(paths) == 3
    assert [s["status"] for s in _scenarios_of(record_id)].count(ScenarioStatus.DONE) == 2
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL


def test_a_duplicate_is_kept_hidden_given_up_and_replaced(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """Two threats the writer tells in the very same words: the one saved second is a duplicate of the first,
    caught before it is saved, with no AI call."""

    def one_story(user_prompt: str) -> dict[str, Any]:
        written = _answer_for(user_prompt)
        if '"threat": "Reserve' in user_prompt:
            return written
        return written | {"scenario_statement": "A cybercriminal could tamper with the SCADA server."}

    chat.responders[AiTask.WRITE_SCENARIO] = one_story
    record_id = _queued_run(["Copy one", "Copy two", "Reserve"], limit=2)
    _deliver_until_done(record_id)
    _, paths = _plan(record_id)
    stored = {s["path_id"]: s for s in _scenarios_of(record_id)}
    copied = next(path_id for path_id in ("p1", "p2") if stored[path_id]["status"] == ScenarioStatus.BLOCKED)
    first = "p2" if copied == "p1" else "p1"
    finding = stored[copied]["findings"][-1]
    assert finding["code"] == FindingCode.NEAR_DUPLICATE and stored[first]["_id"] in finding["message"]
    assert paths[copied]["replaced_by"] == "p3" and stored["p3"]["status"] == ScenarioStatus.DONE
    assert paths[copied]["attempts"] == 1 and len(chat.asked(AiTask.WRITE_SCENARIO)) == 3  # given up at once


def test_a_second_run_of_the_asset_never_copies_what_the_first_run_holds(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """6.1c/6.1d (owner 2026-10-17: "Prevent duplicate scenarios ... against existing scenarios in the
    relevant library or database"): a second run of the asset planned with the same paths. Each repeats the
    first run's scenario of that path, accepted or still to decide, so it is given up before any AI call, with
    no card; with no path left, the set ends partial."""
    first = _queued_run(["Threat 1", "Threat 2"])
    _deliver_until_done(first)
    held = {scenario["path_id"]: scenario["_id"] for scenario in _scenarios_of(first)}
    accepted = {"$set": {"decision": Decision.ACCEPTED}}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": held["p1"]}, accepted)
    written_by_first = len(chat.asked(AiTask.WRITE_SCENARIO))
    again = _queued_run(["Threat 1", "Threat 2"])
    _on_the_asset_of(again, first)
    _deliver_until_done(again)
    run, paths = _plan(again)
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == written_by_first and _scenarios_of(again) == []
    for path in paths.values():
        assert (path["abandoned"], path["abandoned_reason"]) == (True, FindingCode.NEAR_DUPLICATE)
        assert (path["attempts"], path["last_blocker"]) == (0, FindingCode.NEAR_DUPLICATE)
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL


def test_a_path_repeating_a_held_scenario_is_given_up_before_the_ai_and_a_spare_takes_its_place(
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """No limit, a set of 2 of 3 paths: p1 repeats the asset's other run's scenario, so it is given up with no
    write call and no card, and the next set's p3 is written in its place; the set ends complete."""
    first = _queued_run(["Threat 1"])
    _deliver_until_done(first)
    calls_before = len(chat.asked(AiTask.WRITE_SCENARIO))
    again = _queued_run(["Threat 1", "Threat 2", "Threat 3"], first_set=2)
    _on_the_asset_of(again, first)
    _deliver_until_done(again)
    run, paths = _plan(again)
    repeat, spare = paths["p1"], paths["p3"]
    assert (repeat["selected"], repeat["unselected_reason"]) == (
        False,
        UnselectedReason.REPLACED_AFTER_FAILURE,
    )
    assert (repeat["abandoned_reason"], repeat["replaced_by"], repeat["attempts"]) == (
        FindingCode.NEAR_DUPLICATE, "p3", 0,
    )  # fmt: skip
    assert spare["replaces"] == "p1" and spare["served"] and paths["p2"]["served"]
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) - calls_before == 2  # p2 and p3 only
    assert sorted(s["path_id"] for s in _scenarios_of(again)) == ["p2", "p3"]  # no card for p1
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE and run["counts"]["replaced"] == 1


def test_with_no_limit_a_rejected_path_is_replaced_by_the_next_sets_best_path(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """No reserve exists when every path is selected: the next set's best open path takes the blocked one's
    place, so the set is complete and the blocked path is not counted as one that could not be written."""
    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3", "Threat 4"], first_set=2)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert (paths["p1"]["selected"], paths["p1"]["replaced_by"]) == (False, "p3")
    assert paths["p3"]["replaces"] == "p1" and paths["p3"]["served"] and not paths["p4"]["served"]
    assert sorted(run["job"]["set"]) == ["p1", "p2", "p3"]
    assert (run["counts"]["abandoned"], run["counts"]["replaced"], run["counts"]["remaining"]) == (0, 1, 1)
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE


def test_replacements_stop_when_the_sets_write_calls_are_spent(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """A set of 1 may spend MAX_PATH_ATTEMPTS write calls: each path rejected and given up at once, a reserve
    in its place, until the calls are spent; the set stops there with reserves left, its last path given up
    with no replacement."""
    _mismatched_for_threats_named(chat, "Wrong")
    names = [f"Wrong {n}" for n in range(Generation.MAX_PATH_ATTEMPTS + 3)]
    record_id = _queued_run(names, limit=1)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == Generation.MAX_PATH_ATTEMPTS
    tried = [path for path in paths.values() if path["attempts"]]
    assert len(tried) == Generation.MAX_PATH_ATTEMPTS and all(path["attempts"] == 1 for path in tried)
    [last] = [path for path in tried if path["selected"]]
    assert last["abandoned"] and last.get("replaced_by") is None
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL


def test_a_next_set_whose_path_a_reserve_replaced_still_reads_what_was_asked(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """G268 (defect A): `requested` is written once, when the set is queued: a set of 2 whose first path a
    reserve replaced reads requested 2, delivered 2, nothing left (the limit left p4 out: target_reached)."""
    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3", "Threat 4"], limit=2)
    queued = {"outcome": RunActionOutcome.RUNNING, "requested": 2, "delivered": None, "reason": None,
              "remaining": None, "epoch": 1}  # fmt: skip
    _sessions().update_one(
        {"_id": record_id}, {"$set": {"last_action": {"kind": "next_set"}, "last_next_set": queued}}
    )
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert paths["p1"]["replaced_by"] == "p3" and len(run["job"]["set"]) == 3  # the reserve joined the set
    assert run["last_next_set"] == {
        "outcome": RunActionOutcome.COMPLETE, "requested": 2, "delivered": 2,
        "reason": ConflictReason.TARGET_REACHED, "remaining": 0, "epoch": 1,
    }  # fmt: skip
