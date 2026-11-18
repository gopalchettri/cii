"""External evidence is searched when scenarios are WRITTEN (not at plan time): once per batch, for the
threats of the paths being written only, again on every write (a regenerate too) and kept in memory only, an
outage costing a scenario its evidence and never the scenario. The write job runs on the test MongoDB with
the fake chat model and the fake finder (tests/external_intelligence/fakes.py)."""

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.constants import (
    AI_OUTAGE_MESSAGES,
    AiOutage,
    AiTask,
    Collection,
    EvidenceMode,
    EvidenceSearchFailure,
    Generation,
    IntelSource,
    PromptVersion,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import LeaseLost, Unavailable
from app.crud.jobs import JobRepository
from app.domain.intel import evidence
from app.domain.scenario.write import build_scenario_id
from tests.external_intelligence.conftest import Intel
from tests.external_intelligence.fakes import SNAPSHOT, TECHNIQUE, FakeFinder
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    _write_batch,
    chat,
    sent,
)

pytestmark = pytest.mark.usefixtures("story_chat", "sent")

NOW = datetime(2026, 10, 12, tzinfo=UTC)


def _threat_docs(record_id: str) -> dict[str, dict[str, Any]]:
    return {t["name"]: t for t in _sessions().find_one({"_id": record_id})["plan"]["threats"]}


def test_a_batch_searches_once_and_only_for_the_threats_it_writes(intel: Intel) -> None:
    record_id = _queued_run([f"Threat {n}" for n in range(1, 9)], first_set=3)  # 8 planned, 3 asked for
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 1 and len(intel.finder.calls[0]) == 3  # one call, three threats
    assert not any("intel_search" in threat for threat in _threat_docs(record_id).values())  # nothing kept
    stored = _scenarios_of(record_id)
    assert len(stored) == 3 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        content = scenario["content"]
        assert content["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert content["prompt_version"] == PromptVersion.SCENARIO_WRITER_EVIDENCE
        assert content["evidence"][0]["n"] == 1 and content["intel_search"]["query"]


def test_one_search_per_written_batch(intel: Intel) -> None:
    batch = Generation.WRITER_BATCH
    record_id = _queued_run([f"Threat {n}" for n in range(1, batch + 3)])  # one full batch, then 2
    assert _deliver_until_done(record_id) == 2
    assert [len(call) for call in intel.finder.calls] == [batch, 2]


def test_a_threat_shared_by_two_paths_is_searched_once(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _sessions().update_one({"_id": record_id}, {"$set": {"plan.paths.1.steps": ["lib:1"]}})
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls[0]) == 1


def test_a_retry_after_an_outage_searches_again(intel: Intel, story_chat: Any) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    story_chat.queue(AiTask.WRITE_SCENARIO, Unavailable("AI down"))  # the first delivery's set write
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    assert len(intel.finder.calls) == 1
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 2 and len(_scenarios_of(record_id)) == 2
    assert len(intel.finder.calls[1]) == 2  # every threat still to write


def test_an_evidence_outage_holds_the_paths_back_and_a_later_try_writes_them_with_evidence(
    intel: Intel, story_chat: Any
) -> None:
    """G229 (owner 2026-10-13: "never a silent omission or fabricated evidence"): an outage writes nothing
    (no write call is made), keeps nothing on the plan, and gives the job back; the next try searches again
    and writes each story on its evidence."""
    intel.finder.down = True
    record_id = _queued_run(["Threat 1", "Threat 2"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    assert _scenarios_of(record_id) == [] and not story_chat.asked(AiTask.WRITE_SCENARIO)
    assert all(not t.get("intel_search") for t in _threat_docs(record_id).values())  # not kept: a later try
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    intel.finder.down = False
    assert _deliver_until_done(record_id) == 1
    stored = _scenarios_of(record_id)
    assert len(stored) == 2 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        assert scenario["content"]["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert scenario["content"]["evidence"][0]["supports"]  # the claim its marker supports


@pytest.mark.parametrize("where", ["in the search", "around the search"])
def test_an_ai_outage_in_the_evidence_search_reaches_the_job_as_that_outage(
    intel: Intel, story_chat: Any, monkeypatch: pytest.MonkeyPatch, where: str
) -> None:
    """Owner 2026-10-20: with intelligence on, an AI down while the evidence is searched is told as "ai_down"
    (the retry notice and the failed run read it), not as a reasonless evidence-search outage."""
    if where == "in the search":  # the embedding or reranker call the finder makes
        intel.finder.down, intel.finder.outage = True, AiOutage.DOWN
    else:  # the batch search as a whole

        def ai_down(*args: Any, **kwargs: Any) -> Any:
            raise Unavailable(AI_OUTAGE_MESSAGES[AiOutage.DOWN], reason=AiOutage.DOWN)

        monkeypatch.setattr(evidence, "find_evidence", ai_down)
    record_id = _queued_run(["Threat 1", "Threat 2"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable) as error:
        _write_batch(lease)
    assert (error.value.reason, error.value.detail) == (AiOutage.DOWN, AI_OUTAGE_MESSAGES[AiOutage.DOWN])
    assert _scenarios_of(record_id) == [] and not story_chat.asked(AiTask.WRITE_SCENARIO)


def test_a_search_that_breaks_names_its_own_reason_never_a_missing_snapshot(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G265 (laptop E2E 2026-10-16): the local reranker could not load, and the job retried with "the evidence
    search could not be made: no_intelligence_snapshot" while the snapshot was there. The reason given is the
    search's own."""

    def reranker_down(*args: Any, **kwargs: Any) -> Any:
        raise Unavailable("the reranker could not load")

    monkeypatch.setattr(evidence, "find_evidence", reranker_down)
    record_id = _queued_run(["Threat 1"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable) as error:
        _write_batch(lease)
    assert "Unavailable: the reranker could not load" in str(error.value)
    assert EvidenceSearchFailure.NO_SNAPSHOT not in str(error.value)
    assert all(not t.get("intel_search") for t in _threat_docs(record_id).values())  # still not kept


@pytest.mark.parametrize("error", [RuntimeError("a bug in the search"), LeaseLost("run")])
def test_a_search_error_that_is_no_outage_reaches_the_job_runner_and_writes_nothing(
    intel: Intel, story_chat: Any, monkeypatch: pytest.MonkeyPatch, error: Exception
) -> None:
    """A bug or a lost lease in the search is raised as itself, never held back as an outage and retried."""

    def search_raising(*args: Any, **kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(evidence, "find_evidence", search_raising)
    record_id = _queued_run(["Threat 1"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(type(error)):
        _write_batch(lease)
    assert _scenarios_of(record_id) == [] and not story_chat.asked(AiTask.WRITE_SCENARIO)


def _start_regenerate(record_id: str, first: str) -> None:
    _sessions().update_one(
        {"_id": record_id},
        {
            "$set": {
                "status": Status.QUEUED,
                "job.task": TaskName.WRITE_SCENARIOS,
                "job.epoch": 2,
                "job.attempts": 0,
                "job.due_at": NOW,
                "job.lease_until": None,
                "job.batch": [{"path_id": "p1", "replaces": first}],
            }
        },
    )
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 2, TaskName.WRITE_SCENARIOS, "again"))


def test_a_regenerate_searches_again(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1 and len(intel.finder.calls) == 1
    _start_regenerate(record_id, build_scenario_id(record_id, "p1", 1))
    assert len(intel.finder.calls) == 2
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": build_scenario_id(record_id, "p1", 2)})
    assert new["content"]["evidence"] != [] and new["content"]["intel_search"]["query"]
    assert new["content"]["prompt_version"] == PromptVersion.SCENARIO_WRITER_EVIDENCE


def _written_without_evidence(record_id: str) -> dict[str, Any]:
    """The regenerate's new version, checked to be written without evidence, its old one superseded."""
    first = build_scenario_id(record_id, "p1", 1)
    scenarios = get_mongodb()[Collection.SCENARIOS]
    new = scenarios.find_one({"_id": build_scenario_id(record_id, "p1", 2)})
    assert scenarios.find_one({"_id": first})["superseded_by"] == new["_id"]
    assert new["status"] == ScenarioStatus.DONE
    assert new["content"]["prompt_version"] == PromptVersion.SCENARIO_WRITER
    assert (new["content"]["evidence_mode"], new["content"]["evidence"]) == (EvidenceMode.INFERRED, [])
    return new


def test_a_regenerate_of_a_story_whose_threat_has_no_evidence_is_written_without(intel: Intel, story_chat: Any) -> None:
    """Owner 2026-10-19 ("do not block the threat scenario"): its threat's search holds nothing usable, so the
    new version is written without evidence and replaces the old one."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    intel.finder.evidence = ()
    writes = len(story_chat.asked(AiTask.WRITE_SCENARIO))
    _start_regenerate(record_id, build_scenario_id(record_id, "p1", 1))
    _written_without_evidence(record_id)
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == writes + 1


def test_a_regenerate_is_written_in_the_style_of_its_own_delivery(intel: Intel) -> None:
    """A regenerate is written as any other write of its delivery: the first version written while
    intelligence was off, the switch on since, the new version is an evidence story on searched evidence."""
    intel.switch.enabled = False  # the first version: the original writer
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    first = build_scenario_id(record_id, "p1", 1)
    assert "evidence_mode" not in get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})["content"]
    intel.switch.enabled = True
    _start_regenerate(record_id, first)
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": build_scenario_id(record_id, "p1", 2)})
    assert new["content"]["prompt_version"] == PromptVersion.SCENARIO_WRITER_EVIDENCE
    assert new["content"]["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED and len(intel.finder.calls) == 1


def test_a_regenerate_while_off_writes_a_story_again_as_the_original_writer(intel: Intel) -> None:
    """(owner 2026-10-12, the switch: off "means nothing is read, searched or shown"). Before, a story was
    written again as a story, from the evidence kept on the plan, whatever the switch said."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1  # a story: written while on
    intel.switch.enabled = False
    _start_regenerate(record_id, build_scenario_id(record_id, "p1", 1))
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": build_scenario_id(record_id, "p1", 2)})
    assert new["content"]["prompt_version"] == PromptVersion.SCENARIO_WRITER
    assert "evidence_mode" not in new["content"]


def test_the_evidence_an_older_plan_kept_is_never_cited_again(intel: Intel) -> None:
    """A plan saved by an older release keeps a threat's evidence; the regenerate searches again and cites
    only what that search finds."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    kept = {"plan.threats.0.evidence": [TECHNIQUE.as_doc()], "plan.threats.0.intel_search": {"snapshot_id": "s"}}
    _sessions().update_one({"_id": record_id}, {"$set": kept})
    intel.finder.evidence = (replace(TECHNIQUE, source=IntelSource.ATTACK_ENTERPRISE),)
    _start_regenerate(record_id, build_scenario_id(record_id, "p1", 1))
    assert len(intel.finder.calls) == 2  # searched again
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": build_scenario_id(record_id, "p1", 2)})
    assert {e["source"] for e in new["content"]["evidence"]} == {IntelSource.ATTACK_ENTERPRISE}
    assert new["content"]["intel_search"]["snapshot_id"] == SNAPSHOT


def test_a_regenerate_of_a_story_while_the_switch_cannot_be_read_waits_for_it(intel: Intel) -> None:
    """G268: a switch in doubt (its store unread on a fresh worker) reads off, so a regenerate would write the
    story again as the original card, for good. It waits instead, and the delivery is tried again. Before, the
    story lost its evidence and citations with no error."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1  # a story: written while on
    intel.switch.known = False
    with pytest.raises(Unavailable):
        _start_regenerate(record_id, build_scenario_id(record_id, "p1", 1))
    scenarios = get_mongodb()[Collection.SCENARIOS]
    assert scenarios.find_one({"_id": build_scenario_id(record_id, "p1", 1)})["superseded_by"] is None
    assert scenarios.find_one({"_id": build_scenario_id(record_id, "p1", 2)}) is None


def test_a_threat_already_searched_is_searched_again(monkeypatch: pytest.MonkeyPatch) -> None:
    """One search per write: a threat's earlier search is replaced by this batch's."""
    finder = FakeFinder()
    monkeypatch.setattr(evidence, "find_evidence", finder.find_evidence)
    context = {"asset": {"id": 1, "name": "Grid", "category_code": None}, "asset_context": {}, "systems": []}
    run = {"_id": "run", "context": context}
    earlier = {"evidence": [], "intel_search": {"snapshot_id": "older", "failure": None}}
    threats = {"t": {"name": "Threat 1", "type": {"name": "Malware"}} | earlier}
    evidence.attach_evidence(run, threats, {"p1": {"steps": ["t"]}}, ["p1"])
    assert len(finder.calls) == 1
    assert threats["t"]["intel_search"]["snapshot_id"] == SNAPSHOT
    assert [entry["ref"] for entry in threats["t"]["evidence"]] == [TECHNIQUE.ref]
