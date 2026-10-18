"""External evidence is searched when scenarios are WRITTEN (not at plan time): once per batch, for the
threats of the paths being written only, again on every write (a regenerate too) and kept in memory only, an
outage costing a scenario its evidence and never the scenario. The write job runs on the test MongoDB with
the fake chat model and the fake finder (tests/external_intelligence/fakes.py)."""

from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.constants import (
    AiTask,
    AuditAction,
    Collection,
    ErrorCode,
    EvidenceMode,
    EvidenceSearchFailure,
    Generation,
    IntelSource,
    ScenarioStatus,
    Status,
    StoryLimits,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import WRITER_PROMPT_VERSION, scenario_id
from app.worker.external_intelligence.evidence_at_write import EvidenceAtWrite
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


def _audit_rows(record_id: str) -> list[dict[str, Any]]:
    query = {"target.id": record_id, "action": AuditAction.EXTERNAL_INTELLIGENCE_EVIDENCE_USED}
    rows = [row["after"] for row in get_mongodb()[Collection.AUDIT].find(query)]
    return sorted(rows, key=lambda after: -after["threats_searched"])


def test_a_batch_searches_once_and_only_for_the_threats_it_writes(intel: Intel) -> None:
    record_id = _queued_run([f"Threat {n}" for n in range(1, 9)], first_set=3)  # 8 planned, 3 asked for
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 1 and len(intel.finder.calls[0][0]) == 3  # one call, three threats
    assert not any("intel_search" in threat for threat in _threat_docs(record_id).values())  # nothing kept
    stored = _scenarios_of(record_id)
    assert len(stored) == 3 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        content = scenario["content"]
        assert content["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert content["prompt_version"] == StoryLimits.PROMPT_VERSION
        assert content["evidence"][0]["n"] == 1 and content["intel_search"]["query"]


def test_one_audit_row_per_written_batch(intel: Intel) -> None:
    batch = Generation.WRITER_BATCH
    record_id = _queued_run([f"Threat {n}" for n in range(1, batch + 3)])  # one full batch, then 2
    assert _deliver_until_done(record_id) == 2
    first, second = _audit_rows(record_id)
    assert (first["threats_searched"], second["threats_searched"]) == (batch, 2)
    assert first["snapshot_id"] == second["snapshot_id"] == SNAPSHOT
    assert len(intel.finder.calls) == 2


def test_a_threat_shared_by_two_paths_is_searched_once(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _sessions().update_one({"_id": record_id}, {"$set": {"plan.paths.1.steps": ["lib:1"]}})
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls[0][0]) == 1


def test_a_retry_after_an_outage_searches_again(intel: Intel, story_chat: Any) -> None:
    record_id = _queued_run(["Threat 1", "Threat 2"])
    down = {"once": True}
    plain = story_chat.responders[AiTask.WRITE_SCENARIO]

    def down_once(user_prompt: str) -> dict[str, Any]:
        if '"Threat 2"' in user_prompt and down.pop("once", False):
            raise Unavailable("AI down")
        return plain(user_prompt)

    story_chat.responders[AiTask.WRITE_SCENARIO] = down_once
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    assert len(intel.finder.calls) == 1
    assert _deliver_until_done(record_id) == 1
    assert len(intel.finder.calls) == 2 and len(_scenarios_of(record_id)) == 2
    assert len(intel.finder.calls[1][0]) == 1  # only the threat still to write
    assert len(_audit_rows(record_id)) == 2


@pytest.mark.parametrize("fault", ["down", "raises"])
def test_an_evidence_outage_holds_the_paths_back_and_a_later_try_writes_them_with_evidence(
    intel: Intel, story_chat: Any, fault: str
) -> None:
    """G229 (owner 2026-10-13: "never a silent omission or fabricated evidence"): an outage, or a search that
    breaks, writes nothing (no write call is made), keeps nothing on the plan, and gives the job back; the
    next try searches again and writes each story on its evidence. Before, the stories were saved inferred."""
    setattr(intel.finder, fault, True)
    record_id = _queued_run(["Threat 1", "Threat 2"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    assert _scenarios_of(record_id) == [] and not story_chat.asked(AiTask.WRITE_SCENARIO)
    assert all(not t.get("intel_search") for t in _threat_docs(record_id).values())  # not kept: a later try
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    setattr(intel.finder, fault, False)
    assert _deliver_until_done(record_id) == 1
    stored = _scenarios_of(record_id)
    assert len(stored) == 2 and {s["status"] for s in stored} == {ScenarioStatus.DONE}
    for scenario in stored:
        assert scenario["content"]["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED
        assert scenario["content"]["evidence"][0]["supports"]  # the claim its marker supports


def test_a_search_that_breaks_names_its_own_reason_never_a_missing_snapshot(intel: Intel) -> None:
    """G265 (laptop E2E 2026-10-16): the local reranker could not load, and the job retried with "the evidence
    search could not be made: no_intelligence_snapshot" while the snapshot was there. The reason given is now
    the search's own."""
    intel.finder.raises = True
    record_id = _queued_run(["Threat 1"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable) as error:
        _write_batch(lease)
    assert "RuntimeError: a bug in the search" in str(error.value)
    assert EvidenceSearchFailure.NO_SNAPSHOT not in str(error.value)
    assert all(not t.get("intel_search") for t in _threat_docs(record_id).values())  # still not kept


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
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 2, TaskName.WRITE_SCENARIOS, "again"))


def test_a_regenerate_searches_again(intel: Intel) -> None:
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1 and len(intel.finder.calls) == 1
    _start_regenerate(record_id, scenario_id(record_id, "p1", 1))
    assert len(intel.finder.calls) == 2
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert new["content"]["evidence"] != [] and new["content"]["intel_search"]["query"]
    assert new["content"]["prompt_version"] == StoryLimits.PROMPT_VERSION


def test_a_regenerate_of_a_story_whose_threat_has_no_evidence_keeps_the_version_with_no_write_call(
    intel: Intel, story_chat: Any
) -> None:
    """G229: the regenerate path cannot bypass the evidence rule: its threat's search holds nothing usable,
    so the old version stays current with the reason, and no write call is spent."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    intel.finder.evidence = ()
    writes = len(story_chat.asked(AiTask.WRITE_SCENARIO))
    first = scenario_id(record_id, "p1", 1)
    _start_regenerate(record_id, first)
    old = get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})
    assert old["superseded_by"] is None and old["regenerate_error"]["code"] == ErrorCode.EVIDENCE_NOT_FOUND
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == writes


def test_a_regenerate_is_written_in_the_style_of_its_own_delivery(intel: Intel) -> None:
    """A regenerate is written as any other write of its delivery: the first version written while
    intelligence was off, the switch on since, the new version is an evidence story on searched evidence."""
    intel.switch.enabled = False  # the first version: the original writer
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    first = scenario_id(record_id, "p1", 1)
    assert "evidence_mode" not in get_mongodb()[Collection.SCENARIOS].find_one({"_id": first})["content"]
    intel.switch.enabled = True
    _start_regenerate(record_id, first)
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert new["content"]["prompt_version"] == StoryLimits.PROMPT_VERSION
    assert new["content"]["evidence_mode"] == EvidenceMode.SOURCE_DOCUMENTED and len(intel.finder.calls) == 1


def test_a_regenerate_while_off_writes_a_story_again_as_the_original_writer(intel: Intel) -> None:
    """(owner 2026-10-12, the switch: off "means nothing is read, searched or shown"). Before, a story was
    written again as a story, from the evidence kept on the plan, whatever the switch said."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1  # a story: written while on
    intel.switch.enabled = False
    _start_regenerate(record_id, scenario_id(record_id, "p1", 1))
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert new["content"]["prompt_version"] == WRITER_PROMPT_VERSION
    assert "evidence_mode" not in new["content"]


def test_the_evidence_an_older_plan_kept_is_never_cited_again(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """(owner 2026-10-12: "each can be revoked and purged"): a plan saved by an older release keeps a
    threat's evidence; the regenerate searches again and cites only what is approved now."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    kept = {
        "plan.threats.0.evidence": [TECHNIQUE.as_doc()],
        "plan.threats.0.intel_search": {"snapshot_id": "s"},
    }
    _sessions().update_one({"_id": record_id}, {"$set": kept})
    monkeypatch.setattr(intel.feeds, "list_approved_sources", lambda: [IntelSource.ATTACK_ENTERPRISE])
    intel.finder.evidence = (replace(TECHNIQUE, source=IntelSource.ATTACK_ENTERPRISE),)
    _start_regenerate(record_id, scenario_id(record_id, "p1", 1))
    assert len(intel.finder.calls) == 2  # searched again, on the index rebuilt without it
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert {e["source"] for e in new["content"]["evidence"]} == {IntelSource.ATTACK_ENTERPRISE}
    assert new["content"]["intel_search"]["snapshot_id"] == SNAPSHOT


def test_a_search_on_an_index_not_yet_rebuilt_never_cites_the_revoked_source(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The worker's index follows the snapshot pointer only every SWITCH_CACHE_SECONDS, so right after a
    revoke it still holds the revoked source: the batch's approved sources go to the search, which never
    offers it."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    monkeypatch.setattr(intel.feeds, "list_approved_sources", lambda: [IntelSource.ATTACK_ENTERPRISE])
    enterprise = replace(TECHNIQUE, ref="T1195", source=IntelSource.ATTACK_ENTERPRISE)
    intel.finder.evidence = (TECHNIQUE, enterprise)
    _start_regenerate(record_id, scenario_id(record_id, "p1", 1))
    new = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 2)})
    assert {e["source"] for e in new["content"]["evidence"]} == {IntelSource.ATTACK_ENTERPRISE}


def test_a_regenerate_of_a_story_while_the_switch_cannot_be_read_waits_for_it(intel: Intel) -> None:
    """G268: a switch in doubt (its store unread on a fresh worker) reads off, so a regenerate would write the
    story again as the original card, for good. It waits instead, and the delivery is tried again. Before, the
    story lost its evidence and citations with no error."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1  # a story: written while on
    intel.switch.known = False
    with pytest.raises(Unavailable):
        _start_regenerate(record_id, scenario_id(record_id, "p1", 1))
    scenarios = get_mongodb()[Collection.SCENARIOS]
    assert scenarios.find_one({"_id": scenario_id(record_id, "p1", 1)})["superseded_by"] is None
    assert scenarios.find_one({"_id": scenario_id(record_id, "p1", 2)}) is None


def test_a_search_whose_only_records_were_revoked_finds_no_evidence_and_is_no_outage(
    intel: Intel, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Revoked records are cut before the top-k, so a search only they could answer settles with no evidence:
    the regenerate keeps the old version with evidence_not_found and never waits as for an outage."""
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    monkeypatch.setattr(intel.feeds, "list_approved_sources", lambda: [IntelSource.ATTACK_ENTERPRISE])
    _start_regenerate(record_id, scenario_id(record_id, "p1", 1))  # the fake holds mitre_attack_ics only
    old = get_mongodb()[Collection.SCENARIOS].find_one({"_id": scenario_id(record_id, "p1", 1)})
    assert old["superseded_by"] is None and old["regenerate_error"]["code"] == ErrorCode.EVIDENCE_NOT_FOUND


def test_a_threat_already_searched_is_searched_again_reading_the_feeds_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One search per write: a threat's earlier search is replaced by this batch's, and the approved sources
    and their health are read once for the batch."""
    reads: list[str] = []

    class CountedFeeds:
        def list_approved_sources(self) -> list[IntelSource]:
            reads.append("approved")
            return list(IntelSource)

        def list_source_health(self) -> list[Any]:
            reads.append("health")
            return []

    class NoAudit:
        def create_audit_record(self, *args: Any, **kwargs: Any) -> None:
            return None

    finder = FakeFinder()
    context = {"asset": {"id": 1, "name": "Grid", "category_code": None}, "asset_context": {}, "systems": []}
    run = {"_id": "run", "context": context | {"missing_facts": []}}
    earlier = {"evidence": [], "intel_search": {"snapshot_id": "older", "failure": None}}
    threats = {"t": {"name": "Threat 1", "type": {"name": "Malware"}} | earlier}
    progress = SimpleNamespace(paths={"p1": {"steps": ["t"]}})
    EvidenceAtWrite(run, threats, progress, finder, CountedFeeds(), NoAudit()).attach(["p1"])  # type: ignore[arg-type]
    assert len(finder.calls) == 1 and sorted(reads) == ["approved", "health"]
    assert threats["t"]["intel_search"]["snapshot_id"] == SNAPSHOT
    assert [entry["ref"] for entry in threats["t"]["evidence"]] == [TECHNIQUE.ref]
