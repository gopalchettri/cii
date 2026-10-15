"""G229 (owner 2026-10-13): with external intelligence on, the final output holds zero scenarios without
qualifying evidence, enforced in code with no AI call added: a threat whose search found nothing is searched
once more with other words, then its path fails for good before any write call; a marker without its claim,
or a citation its entry does not support is final at once (no rewrite asked, no retry). G250 (owner
2026-10-15): a story citing none of its sources is kept with the closest one shown as related intelligence,
never numbered, with no AI call. The switch is read once per batch; each cited entry keeps its dates, role
and claim."""

import dataclasses
from typing import Any

import pytest

from app.core.constants import (
    AiTask,
    Applicability,
    ErrorCode,
    EvidenceFact,
    EvidenceRole,
    FindingCode,
    ScenarioStatus,
    TaskName,
)
from app.core.database import get_mongodb
from app.core.exceptions import Unavailable
from app.data_access.job_records import JobLease
from app.data_access.sessions import SessionRepository
from app.engine.scenarios.writing.evidence_checks import evidence_findings
from app.engine.scenarios.writing.evidence_gate import evidence_problem
from app.models.external_intelligence.evidence import Evidence
from app.models.writing import PathFailure, ScenarioDraft
from app.worker.tasks import writing
from tests.external_intelligence.conftest import STORY_PLAIN, Intel
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _story_brief
from tests.planner_samples import CONTEXT
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _deliver_until_done,
    _queued_run,
    _scenarios_of,
    _sessions,
    chat,
    sent,
)

pytestmark = pytest.mark.usefixtures("story_chat", "sent")

#: An entry as the real sources give it: its facts are EvidenceFact sentences, so what it names is exact.
NAMED = Evidence(
    "T0839", TECHNIQUE.kind, TECHNIQUE.source, "Module Firmware", TECHNIQUE.url, 91.0,
    (EvidenceFact.USED_BY.format(name="Sandworm Team", what="a threat group"),
     EvidenceFact.MITIGATED_BY.format(mitigations="Code Signing")),
)  # fmt: skip


def _draft(statement: str, links: tuple[tuple[int, str], ...] = ()) -> ScenarioDraft:
    return ScenarioDraft("T", statement, "Loss of control could follow.", (), "SCADA server", (), links)


def _codes(draft: ScenarioDraft, entry: Evidence) -> set[str]:
    return {finding.code for finding in evidence_findings(draft, _story_brief(entry))}


def test_a_citation_counts_only_when_its_sentence_states_what_the_entry_states() -> None:
    """Run 03276384: 6 of 9 citations were "attackers did this before [1]"; such a sentence names nothing the
    entry names (here Sandworm) and does not count; naming it does. A marker needs its claim; none cited,
    nothing finished."""
    generic = "Attackers have tampered with device firmware in this way before [1]."
    named = "The Sandworm group has tampered with device firmware in this way before [1]."
    claim = ((1, "tampered with device firmware"),)
    assert _codes(_draft(generic, claim), NAMED) == {FindingCode.CITATION_UNSUPPORTED}
    assert _codes(_draft(named, claim), NAMED) == set()
    assert _codes(_draft(named), NAMED) == {FindingCode.EVIDENCE_LINK_MISSING}
    assert _codes(_draft(STORY_PLAIN), NAMED) == {FindingCode.NO_EVIDENCE_CITED}


def test_an_unsupported_marker_goes_with_its_past_event_sentence_and_the_story_stays() -> None:
    """The plan check (an existing call) also returns unsupported_citations (an uncited number is ignored);
    no rewrite is asked for it. G252 (owner 2026-10-15): instead of losing the story, the sentence claiming
    a past event with that marker is taken out in code, and the reviewer is told."""
    from tests.external_intelligence.writing.test_evidence_story import _DRAFT
    from tests.test_scenario_writing import _writer

    flagged = {"consistent": True, "problems": [], "unsupported_citations": ["[1]", 7]}
    writer, fake = _writer([_DRAFT.to_answer()], [flagged])
    written = writer.write_scenario(_story_brief(TECHNIQUE))
    assert not written.blocked and not fake.asked(AiTask.REWRITE_SCENARIO)
    assert "rogue firmware update" not in written.draft.statement and "[1]" not in written.draft.statement
    codes = {finding.code for finding in written.findings}
    assert FindingCode.CITATION_REMOVED in codes and FindingCode.CITATION_UNSUPPORTED not in codes


def test_a_story_citing_nothing_shows_its_closest_source_and_one_with_no_source_is_never_done() -> None:
    """G250: citing none of its sources, the card is done with the best-scored source as related
    intelligence (no number, no claim, mode "related"); the record's own guard still keeps a story with no
    source at all hidden, never served (the evidence gate stops it before writing)."""
    from app.core.constants import EvidenceMode, PlanCheckStatus, Route
    from app.engine.scenarios.writing.scenario_record import written_record
    from app.models.writing import PlanCheck, WrittenScenario
    from tests.test_scenario_writing import _plan_threat

    weaker = dataclasses.replace(NAMED, ref="T0800", score=60.0)
    threat = _plan_threat(evidence=[weaker.as_doc(), NAMED.as_doc()], intel_search={"query": "q"})
    check = PlanCheck(PlanCheckStatus.CONSISTENT)
    written = WrittenScenario(_draft(STORY_PLAIN), (), check, Route.STANDALONE, False)
    run = {"_id": "r1", "entity_id": 86, "asset_id": 5, "context": {"systems": CONTEXT.systems}}
    path = {"path_id": "p1", "category": "Tampering", "steps": [threat["key"]], "rank": 1, "systems": [321]}
    record = written_record(run, path, threat, _story_brief(weaker, NAMED), written)
    content = record["content"]
    assert record["status"] == ScenarioStatus.DONE and content["evidence"] == []
    assert [item["ref"] for item in content["related_evidence"]] == ["T0839"]  # the best score, not the first
    assert "n" not in content["related_evidence"][0] and content["evidence_mode"] == EvidenceMode.RELATED
    nothing = written_record(run, path, _plan_threat(evidence=[]), _story_brief(), written)
    assert nothing["status"] == ScenarioStatus.BLOCKED and nothing["content"]["related_evidence"] == []


def test_the_gate_fails_a_threat_with_no_evidence_for_good_and_holds_back_an_outage() -> None:
    settled = {"snapshot_id": "s1", "failure": None, "attempts": [{"query": "first"}]}
    failure = evidence_problem({"evidence": [], "intel_search": settled})
    assert isinstance(failure, PathFailure) and failure.final and failure.code == ErrorCode.EVIDENCE_NOT_FOUND
    assert "2 search(es)" in failure.message
    assert isinstance(evidence_problem({"intel_search": settled | {"failure": "down"}}), Unavailable)
    assert isinstance(evidence_problem({"intel_search": None}), Unavailable)  # never searched: no snapshot
    assert evidence_problem({"evidence": [{"ref": "T0839"}], "intel_search": settled}) is None
    # G254: nothing passed, but the search kept its closest candidate: the story is written, never empty
    assert (
        evidence_problem({"evidence": [], "nearest_evidence": [{"ref": "T0839"}], "intel_search": settled})
        is None
    )


def test_nothing_passing_writes_the_story_with_its_nearest_source_shown_and_never_cited(
    intel: Intel, story_chat: Any
) -> None:
    """G254 (owner 2026-10-15: "provide at least 1 which is nearby, do not make it empty"): the writer gets no
    entry (a weak match never becomes a footnote); the card is done with the closest candidate shown."""
    intel.finder.evidence, intel.finder.nearest = (), TECHNIQUE
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (card,) = _scenarios_of(record_id)
    content = card["content"]
    assert card["status"] == ScenarioStatus.DONE and content["evidence"] == []
    assert [item["ref"] for item in content["related_evidence"]] == ["T0839"]
    assert content["evidence_mode"] == "nearest"
    (prompt,) = story_chat.asked(AiTask.WRITE_SCENARIO)
    assert "T0839" not in str(prompt) and "Module Firmware" not in str(prompt)  # never given to the writer
    threat = _sessions().find_one({"_id": record_id})["plan"]["threats"][0]
    assert [item["ref"] for item in threat["nearest_evidence"]] == ["T0839"]


def test_nothing_found_is_searched_again_in_other_words_then_failed_with_no_write_call(
    intel: Intel, story_chat: Any
) -> None:
    intel.finder.evidence = ()
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    first, again = (requests[0].text for requests, _ in intel.finder.calls)
    assert len(intel.finder.calls) == 2 and first != again and "Kind of attack" in again
    (card,) = _scenarios_of(record_id)
    assert card["status"] == ScenarioStatus.FAILED and card["failure"]["code"] == ErrorCode.EVIDENCE_NOT_FOUND
    assert not story_chat.asked(AiTask.WRITE_SCENARIO)  # no AI call spent on a scenario that cannot be proven
    plan = _sessions().find_one({"_id": record_id})["plan"]
    assert plan["paths"][0]["abandoned"] and plan["paths"][0]["attempts"] == 1
    search = plan["threats"][0]["intel_search"]
    assert len(search["attempts"]) == 1 and search["searched_at"]


def test_a_story_citing_nothing_is_kept_with_its_closest_source_and_asks_no_rewrite(
    intel: Intel, story_chat: Any
) -> None:
    """G250 (owner 2026-10-15): the writer ignored good evidence (run 0a8456d0: 2 of 6 cards lost so): the
    card is finished with its closest source as related intelligence, after ONE write call and no rewrite."""
    answer = story_chat.responders[AiTask.WRITE_SCENARIO]
    story_chat.responders[AiTask.WRITE_SCENARIO] = lambda prompt: answer(prompt) | {
        "scenario_statement": STORY_PLAIN, "evidence_links": [],
    }  # fmt: skip
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (kept,) = _scenarios_of(record_id)
    assert kept["status"] == ScenarioStatus.DONE and kept["content"]["evidence"] == []
    assert len(kept["content"]["related_evidence"]) == 1
    assert FindingCode.NO_EVIDENCE_CITED in {finding["code"] for finding in kept["findings"]}
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == 1 and not story_chat.asked(AiTask.REWRITE_SCENARIO)
    path = _sessions().find_one({"_id": record_id})["plan"]["paths"][0]
    assert not path.get("abandoned")


def test_the_switch_is_read_once_per_batch(intel: Intel) -> None:
    """P6: turned off while a batch runs, the batch still writes as it began (evidence stories, searched),
    never a story with no search."""
    record_id = _queued_run(["Threat 1"])
    lease = JobLease.claim(_sessions(), record_id, 1, TaskName.WRITE_SCENARIOS, "one")
    assert lease is not None
    db = get_mongodb()
    run = SessionRepository(db).find_for_writing(record_id)
    library = writing.get_library_service().get_threat_library()
    batch = writing.BatchWriter(lease, run, db, writing.get_chat_model(), library)
    intel.switch.enabled = False
    batch.write()
    (scenario,) = _scenarios_of(record_id)
    assert scenario["status"] == ScenarioStatus.DONE and len(intel.finder.calls) == 1
    assert scenario["content"]["evidence"][0]["n"] == 1


def test_each_cited_entry_keeps_its_dates_its_role_and_its_claim(intel: Intel) -> None:
    confirmed = Evidence(
        "CVE-2024-0001", TECHNIQUE.kind, TECHNIQUE.source, "Flaw", TECHNIQUE.url, 80.0, TECHNIQUE.facts,
        Applicability.CONFIRMED, published="2024-01-05", fetched_at="2026-10-12T00:00:00",
        role=EvidenceRole.DIRECT,
    )  # fmt: skip
    intel.finder.evidence = (confirmed,)
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (scenario,) = _scenarios_of(record_id)
    (entry,) = scenario["content"]["evidence"]
    dated = (entry["published"], entry["fetched_at"], entry["role"])
    assert dated == ("2024-01-05", "2026-10-12T00:00:00", EvidenceRole.DIRECT)
    assert entry["searched_at"] and entry["supports"]


def _scripted_searches(intel: Intel, monkeypatch: pytest.MonkeyPatch, *answers: dict[str, Any]) -> None:
    """Each search of the run answers the next of `answers` (evidence / nearest), in order."""
    finder, queue = intel.finder, iter(answers)

    def scripted(request: Any, stale: bool) -> Any:
        plain = type(finder)._result_of(finder, request, stale)  # noqa: SLF001 - the fake's own answer
        return dataclasses.replace(plain, **next(queue))

    monkeypatch.setattr(intel.finder, "_result_of", scripted)


def test_over_the_tries_a_search_with_real_evidence_wins_else_the_best_nearest_is_kept(
    intel: Intel, story_chat: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G254: a threat is searched again with other words when nothing passed; the better nearest of the two
    tries is kept, and a try that finds real evidence makes the nearest irrelevant."""
    weak, weaker = (
        dataclasses.replace(TECHNIQUE, ref=ref, score=score)
        for ref, score in (("T0001", 40.0), ("T0002", 20.0))
    )
    _scripted_searches(
        intel, monkeypatch, {"evidence": (), "nearest": weak}, {"evidence": (), "nearest": weaker}
    )
    first = _queued_run(["Threat 1"])
    assert _deliver_until_done(first) == 1
    threat = _sessions().find_one({"_id": first})["plan"]["threats"][0]
    assert threat["evidence"] == [] and [item["ref"] for item in threat["nearest_evidence"]] == ["T0001"]
    _scripted_searches(
        intel, monkeypatch, {"evidence": (), "nearest": weak}, {"evidence": (TECHNIQUE,), "nearest": None}
    )
    second = _queued_run(["Threat 1"])
    assert _deliver_until_done(second) == 1
    threat = _sessions().find_one({"_id": second})["plan"]["threats"][0]
    assert [item["ref"] for item in threat["evidence"]] == ["T0839"] and threat["nearest_evidence"] == []
