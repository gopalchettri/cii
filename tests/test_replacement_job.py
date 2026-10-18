"""G229 in the write job (owner 2026-10-13: "Reject the invalid candidate and follow the bounded replacement
policy ... final_scenario_count <= TOTAL_SCENARIO_COUNT"). A scenario a final blocker keeps after its one
rewrite (here the reviewer's mismatch, or a duplicate) gives its path up at once; with TOTAL_SCENARIO_COUNT
N a reserve takes its place in the same set, the selected count never grows; with 0 there is no reserve and
nothing is padded. The job runs on the test MongoDB with the fake chat model."""

import json
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
)
from app.core.database import get_mongodb
from app.models.scenario.views import run_coverage
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

_REWRITE = "BRIEF:\n" + json.dumps({"entry_point_options": ["SCADA server"], "threat": {"threat": "Rewrite"}})
_MISMATCH = FindingMessage.SCENARIO_MISMATCH.format(parts="threat")


def _mismatched_for_threats_named(fake: FakeChatModel, prefix: str) -> None:
    """The fake reviewer, finding another threat told for the threats named `prefix`..., draft and rewrite."""
    fake.responders[AiTask.REWRITE_SCENARIO] = lambda _: _answer_for(_REWRITE)
    fake.responders[AiTask.PLAN_CHECK] = lambda prompt: {
        "rules": {"1": "holds"}, "same_threat": f'"threat": "{prefix}' not in prompt, "same_impact": True,
    }  # fmt: skip


def _plan(record_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    run = _sessions().find_one({"_id": record_id})
    return run, {path["path_id"]: path for path in run["plan"]["paths"]}


def test_a_rejected_path_is_replaced_by_a_reserve_and_the_limit_holds(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3", "Threat 4"], limit=2)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    failed, reserve = paths["p1"], paths["p3"]
    assert (failed["selected"], failed["abandoned"], failed["attempts"]) == (False, True, 1)
    assert (failed["abandoned_reason"], failed["replaced_by"]) == (FindingCode.SCENARIO_MISMATCH, "p3")
    assert reserve["selected"] and reserve["replaces"] == "p1" and reserve["served"]
    assert not paths["p4"]["selected"] and sum(path["selected"] for path in paths.values()) == 2
    assert len(chat.asked(AiTask.REWRITE_SCENARIO)) == 1  # the one rewrite, then given up at once
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 3  # p1 once, p2, p3: no retry of p1
    done = [s for s in _scenarios_of(record_id) if s["status"] == ScenarioStatus.DONE]
    assert sorted(s["path_id"] for s in done) == ["p2", "p3"]
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE and run["counts"]["replaced"] == 1
    coverage = run_coverage(run)
    assert coverage is not None and coverage["finished"] == 2 <= coverage["limit"]
    assert coverage["given_up"] == [
        {"path_id": "p1", "reason": FindingCode.SCENARIO_MISMATCH, "replaced_by": "p3"}
    ]


def test_with_no_limit_a_rejected_path_is_never_replaced_and_nothing_is_padded(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
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
    assert not chat.asked(AiTask.REWRITE_SCENARIO)


def test_a_second_run_of_the_asset_never_copies_what_the_first_run_holds(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """6.1c/6.1d (owner 2026-10-17: "Prevent duplicate scenarios ... against existing scenarios in the
    relevant library or database"): a second run of the asset writes the same paths again, under the same path
    ids. Each is compared with the first run's scenario of that path, accepted or still to decide, and kept
    hidden naming it."""
    first = _queued_run(["Threat 1", "Threat 2"])
    _deliver_until_done(first)
    held = {scenario["path_id"]: scenario["_id"] for scenario in _scenarios_of(first)}
    accepted = {"$set": {"decision": Decision.ACCEPTED}}
    get_mongodb()[Collection.SCENARIOS].update_one({"_id": held["p1"]}, accepted)
    again = _queued_run(["Threat 1", "Threat 2"])
    _sessions().update_one(
        {"_id": again}, {"$set": {"asset_id": _sessions().find_one({"_id": first})["asset_id"]}}
    )
    _deliver_until_done(again)
    copies = _scenarios_of(again)
    assert [scenario["path_id"] for scenario in copies] == ["p1", "p2"]
    for scenario in copies:
        finding = scenario["findings"][-1]
        assert scenario["status"] == ScenarioStatus.BLOCKED and finding["code"] == FindingCode.NEAR_DUPLICATE
        assert held[scenario["path_id"]] in finding["message"]


def test_replacements_stop_when_the_sets_write_calls_are_spent(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """A set of 1 may spend MAX_PATH_ATTEMPTS write calls: every candidate rejected, the set stops there
    with reserves left, its last path given up with no replacement."""
    _mismatched_for_threats_named(chat, "Wrong")
    names = [f"Wrong {n}" for n in range(Generation.MAX_PATH_ATTEMPTS + 3)]
    record_id = _queued_run(names, limit=1)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == Generation.MAX_PATH_ATTEMPTS
    tried = [path for path in paths.values() if path["attempts"]]
    assert (
        len(tried) == Generation.MAX_PATH_ATTEMPTS and sum(path["selected"] for path in paths.values()) == 1
    )
    last = next(path for path in tried if path["selected"])
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


def test_the_results_name_a_given_up_paths_threat_and_its_own_reason(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """G268: the results' coverage.given_up reads each path's newest card (one query): the threat's name and
    the blocked draft's own sentence for its reason, never just a code and an id."""
    from app.data_access.scenario.repository import scenarios
    from app.models.scenario.views import explain_given_up

    _mismatched_for_threats_named(chat, "Wrong")
    record_id = _queued_run(["Wrong one", "Threat 2", "Threat 3", "Threat 4"], limit=2)
    _deliver_until_done(record_id)
    coverage = run_coverage(_plan(record_id)[0])
    assert coverage is not None
    found = scenarios.list(fields="given_up", sort="version", session_id=record_id, path_id_in=["p1"])
    cards = {card["path_id"]: card for card in found}
    [entry] = explain_given_up(coverage["given_up"], cards)
    assert (entry["threat"], entry["reason"], entry["replaced_by"]) == (
        "Wrong one",
        FindingCode.SCENARIO_MISMATCH,
        "p3",
    )
    assert entry["message"] == _MISMATCH
