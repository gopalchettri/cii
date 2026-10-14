"""External evidence is searched when scenarios are WRITTEN (not at plan time): once per batch, for the
threats of the paths being written only, kept on the plan so no path is searched twice and a regenerate keeps
its numbering, an outage costing a scenario its evidence and never the scenario. The write job runs on
the test MongoDB with the fake chat model and the fake finder (tests/external_intelligence/fakes.py)."""

from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ErrorCode,
    EvidenceMode,
    ScenarioStatus,
    Status,
    StoryLimits,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.job_records import JobLease
from app.engine.scenarios.writing.scenario_record import scenario_id
from app.worker.tasks import writing
from tests.external_intelligence.conftest import Intel
from tests.external_intelligence.fakes import SNAPSHOT
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

pytestmark = pytest.mark.usefixtures("story_chat", "sent")

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _threat_docs(record_id: str) -> dict[str, dict[str, Any]]:
    return {t["name"]: t for t in _sessions().find_one({"_id": record_id})["plan"]["threats"]}


def _audit_rows(record_id: str) -> list[dict[str, Any]]:
    query = {"target.id": record_id, "action": AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED}
    rows = [row["after"] for row in get_mongodb()[Collection.AUDIT].find(query)]
    return sorted(rows, key=lambda after: -after["threats_searched"])


def test_a_batch_searches_once_and_only_for_the_threats_it_writes(intel: Intel) -> None:
    record_id = _queued_run([f"Threat {n}" for n in range(1, 9)], first_set=3)  # 8 planned, 3 asked for
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 1 and len(intel.finder.calls[0][0]) == 3  # one call, three threats
    searched = [name for name, threat in _threat_docs(record_id).items() if threat.get("intel_search")]
    assert sorted(searched) == ["Threat 1", "Threat 2", "Threat 3"]  # the 5 not asked for are never searched
    stored = _scenarios_of(record_id)
    assert len(stored) == 3 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        content = scenario["content"]
        assert content["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert content["prompt_version"] == StoryLimits.PROMPT_VERSION
        assert content["evidence"][0]["n"] == 1 and content["intel_search"]["query"]


def test_one_audit_row_per_written_batch(intel: Intel) -> None:
    record_id = _queued_run([f"Threat {n}" for n in range(1, 9)])  # batches of 6 and 2
    assert _deliver_until_done(record_id) == 2
    first, second = _audit_rows(record_id)
    assert (first["threats_searched"], second["threats_searched"]) == (6, 2)
    assert first["snapshot_id"] == second["snapshot_id"] == SNAPSHOT
    assert len(intel.finder.calls) == 2


def test_a_threat_shared_by_two_paths_is_searched_once(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _sessions().update_one({"_id": record_id}, {"$set": {"plan.paths.1.steps": ["lib:1"]}})
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls[0][0]) == 1


def test_a_retry_after_an_outage_does_not_search_again(intel: Intel, story_chat: Any) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    down = {"once": True}
    plain = story_chat.responders[AiTask.WRITE_SCENARIO]

    def down_once(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt and down.pop("once", False):
            raise Unavailable("AI down")
        return plain(user_prompt)

    story_chat.responders[AiTask.WRITE_SCENARIO] = down_once
    lease = JobLease.claim(_sessions(), record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        writing.write_batch(lease)
    assert lease.give_back(0) and len(intel.finder.calls) == 1
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 1 and len(_scenarios_of(record_id)) == 2  # no second search
    assert len(_audit_rows(record_id)) == 1


@pytest.mark.parametrize("fault", ["down", "raises"])
def test_an_evidence_outage_holds_the_paths_back_and_a_later_try_writes_them_with_evidence(
    intel: Intel, story_chat: Any, fault: str
) -> None:
    """G229 (owner 2026-10-13: "never a silent omission or fabricated evidence"): an outage, or a search that
    breaks, writes nothing (no write call is made), keeps nothing on the plan, and gives the job back; the
    next try searches again and writes each story on its evidence. Before, the stories were saved inferred."""
    setattr(intel.finder, fault, True)
    record_id = _queued_run(["Threat 1", "Threat 2"])
    lease = JobLease.claim(_sessions(), record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        writing.write_batch(lease)
    assert _scenarios_of(record_id) == [] and not story_chat.asked(AiTask.WRITE_SCENARIO)
    assert all(not t.get("intel_search") for t in _threat_docs(record_id).values())  # not kept: a later try
    assert lease.give_back(0)
    setattr(intel.finder, fault, False)
    assert _deliver_until_done(record_id) == 1
    stored = _scenarios_of(record_id)
    assert len(stored) == 2 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        assert scenario["content"]["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert scenario["content"]["evidence"][0]["supports"]  # the claim its marker supports


def _start_regenerate(record_id: str, first: str) -> None:
    _sessions().update_one(
        {"_id": record_id},
        {
            "$set": {
                "status": Status.QUEUED,
                "active": True,
                "job.task": TaskName.WRITE_SCENARIOS,
                "job.epoch": 2,
                "job.attempts": 0,
                "job.due_at": NOW,
                "job.lease_until": None,
                "job.batch": [{"path_id": "p1", "replaces": first}],
            }
        },
    )
    writing.write_batch(JobLease.claim(_sessions(), record_id, 2, TaskName.WRITE_SCENARIOS, "again"))


def test_a_regenerate_keeps_the_evidence_numbering_and_searches_nothing(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1 and len(intel.finder.calls) == 1
    first = scenario_id(record_id, "p1", 1)
    _start_regenerate(record_id, first)
    assert len(intel.finder.calls) == 1
    scenarios = get_mongodb()[Collection.SCENARIOS]
    old, new = (
        scenarios.find_one({"_id": first}),
        scenarios.find_one({"_id": scenario_id(record_id, "p1", 2)}),
    )
    assert new["content"]["evidence"] == old["content"]["evidence"] != []
    assert new["content"]["intel_search"] == old["content"]["intel_search"]
    assert new["content"]["prompt_version"] == StoryLimits.PROMPT_VERSION


def test_a_regenerate_of_a_story_whose_threat_has_no_evidence_keeps_the_version_with_no_write_call(
    intel: Intel, story_chat: Any
) -> None:
    """G229: the regenerate path cannot bypass the evidence rule: its threat's settled search holds nothing
    usable, so the old version stays current with the reason, and no write call is spent."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    _sessions().update_one({"_id": record_id}, {"$set": {"plan.threats.0.evidence": []}})
    writes = len(story_chat.asked(AiTask.WRITE_SCENARIO))
    first = scenario_id(record_id, "p1", 1)
    _start_regenerate(record_id, first)
    old = get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})
    assert old["superseded_by"] is None and old["regenerate_error"]["code"] == ErrorCode.EVIDENCE_NOT_FOUND
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == writes


def test_a_regenerate_keeps_the_original_style_of_the_scenario_it_replaces(intel: Intel) -> None:
    intel.switch.enabled = (
        False  # the first version is written while intelligence is off: the original writer
    )
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    first = scenario_id(record_id, "p1", 1)
    original = get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})
    assert "evidence_mode" not in original["content"]
    intel.switch.enabled = True  # turned on since: the regenerate still writes the original style
    _start_regenerate(record_id, first)
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert new["content"]["prompt_version"] == original["content"]["prompt_version"]
    assert "evidence_mode" not in new["content"] and intel.finder.calls == []
