"""G229 in the write job (owner 2026-10-13: "Do not retry an AI request when validation fails. Reject the
invalid candidate and follow the bounded replacement policy ... final_scenario_count <=
TOTAL_SCENARIO_COUNT"). A scenario a final rule rejects (here a vague line, or a near copy) gives its path up
at once, with no rewrite call; with TOTAL_SCENARIO_COUNT N a reserve takes its place in the same set, the
selected count never grows; with 0 there is no reserve and nothing is padded. The job runs on the test
MongoDB with the fake chat model."""

from typing import Any

import pytest

from app.core.constants import AiTask, FindingCode, Generation, RunActionOutcome, ScenarioStatus
from app.models.coverage import run_coverage
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


def _vague_for_threats_named(prefix: str) -> Any:
    """The fake writer, writing a line that states no action for the threats named `prefix`..."""

    def answer(user_prompt: str) -> dict[str, Any]:
        written = _answer_for(user_prompt)
        if f'"threat": "{prefix}' in user_prompt:
            written["scenario_statement"] += " The attacker may exploit vulnerabilities to stop it."
        return written

    return answer


def _plan(record_id: str) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    run = _sessions().find_one({"_id": record_id})
    return run, {path["path_id"]: path for path in run["plan"]["paths"]}


def test_a_rejected_path_is_replaced_by_a_reserve_and_the_limit_holds(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    chat.responders[AiTask.WRITE_SCENARIO] = _vague_for_threats_named("Vague")
    record_id = _queued_run(["Vague one", "Threat 2", "Threat 3", "Threat 4"], limit=2)
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    failed, reserve = paths["p1"], paths["p3"]
    assert (failed["selected"], failed["abandoned"], failed["attempts"]) == (False, True, 1)
    assert (failed["abandoned_reason"], failed["replaced_by"]) == (FindingCode.VAGUE_PHRASE, "p3")
    assert reserve["selected"] and reserve["replaces"] == "p1" and reserve["served"]
    assert not paths["p4"]["selected"] and sum(path["selected"] for path in paths.values()) == 2
    assert not chat.asked(AiTask.REWRITE_SCENARIO)  # a final rule never asks for the rewrite
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 3  # p1 once, p2, p3: no retry of p1
    done = [s for s in _scenarios_of(record_id) if s["status"] == ScenarioStatus.DONE]
    assert sorted(s["path_id"] for s in done) == ["p2", "p3"]
    assert run["last_action"]["outcome"] == RunActionOutcome.COMPLETE and run["counts"]["replaced"] == 1
    coverage = run_coverage(run)
    assert coverage is not None and coverage["finished"] == 2 <= coverage["limit"]
    assert coverage["given_up"] == [
        {"path_id": "p1", "reason": FindingCode.VAGUE_PHRASE, "replaced_by": "p3"}
    ]


def test_with_no_limit_a_rejected_path_is_never_replaced_and_nothing_is_padded(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    chat.responders[AiTask.WRITE_SCENARIO] = _vague_for_threats_named("Vague")
    record_id = _queued_run(["Vague one", "Threat 2", "Threat 3"])
    _deliver_until_done(record_id)
    run, paths = _plan(record_id)
    assert paths["p1"]["abandoned"] and paths["p1"].get("replaced_by") is None
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 3 and len(paths) == 3
    assert [s["status"] for s in _scenarios_of(record_id)].count(ScenarioStatus.DONE) == 2
    assert run["last_action"]["outcome"] == RunActionOutcome.PARTIAL


def test_a_near_copy_is_kept_hidden_given_up_and_replaced(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """Two threats the writer tells as one story: the one saved second is a near copy of the first."""

    def one_story(user_prompt: str) -> dict[str, Any]:
        if '"threat": "Reserve' in user_prompt:
            return _answer_for(user_prompt)
        same_parts = {
            "target": "SCADA server", "entry_point": "SCADA server", "preconditions": [],
            "mechanism": "pushes modified firmware to the SCADA server",
            "consequence": "operators lose control",
        }  # fmt: skip
        return _answer_for(user_prompt) | {"anatomy": same_parts}

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


def test_replacements_stop_when_the_sets_write_calls_are_spent(chat: FakeChatModel) -> None:  # noqa: F811 - the imported fixture
    """A set of 1 may spend MAX_PATH_ATTEMPTS write calls: every candidate rejected, the set stops there
    with reserves left, its last path given up with no replacement."""
    chat.responders[AiTask.WRITE_SCENARIO] = _vague_for_threats_named("Vague")
    names = [f"Vague {n}" for n in range(Generation.MAX_PATH_ATTEMPTS + 3)]
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
