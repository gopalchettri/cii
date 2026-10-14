"""G229 (owner 2026-10-13): with external intelligence on, the final output holds zero scenarios without
qualifying evidence, enforced in code with no AI call added: a threat whose search found nothing is searched
once more with other words, then its path fails for good before any write call; a story citing nothing, a
marker without its claim, or a citation its entry does not support is final at once (no rewrite asked, no
retry); the switch is read once per batch; each cited entry keeps its dates, role and claim."""

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


def test_a_marker_the_existing_plan_check_names_unsupported_is_final_with_no_rewrite() -> None:
    """The plan check (an existing call) also returns unsupported_citations: a marker it names, of those the
    story cites, is final at once; no rewrite is asked for it alone, and an uncited number is ignored."""
    from tests.external_intelligence.writing.test_evidence_story import _DRAFT
    from tests.test_scenario_writing import _writer

    flagged = {"consistent": True, "problems": [], "unsupported_citations": ["[1]", 7]}
    writer, fake = _writer([_DRAFT.to_answer()], [flagged])
    written = writer.write_scenario(_story_brief(TECHNIQUE))
    assert written.blocked and written.final and not fake.asked(AiTask.REWRITE_SCENARIO)
    assert [f.message for f in written.findings if f.code == FindingCode.CITATION_UNSUPPORTED] == [
        "The marker(s) [1] sit by claims their evidence entries do not support."
    ]


def test_a_story_citing_nothing_is_never_saved_done_whatever_made_it() -> None:
    """The record's own guard: a draft no rule blocked (a fault elsewhere) is kept hidden, never served."""
    from app.core.constants import PlanCheckStatus, Route
    from app.engine.scenarios.writing.scenario_record import written_record
    from app.models.writing import PlanCheck, WrittenScenario
    from tests.test_scenario_writing import _plan_threat

    threat = _plan_threat(evidence=[TECHNIQUE.as_doc()], intel_search={"query": "q"})
    check = PlanCheck(PlanCheckStatus.CONSISTENT)
    written = WrittenScenario(_draft(STORY_PLAIN), (), check, Route.STANDALONE, False)
    run = {"_id": "r1", "entity_id": 86, "asset_id": 5, "context": {"systems": CONTEXT.systems}}
    path = {"path_id": "p1", "category": "Tampering", "steps": [threat["key"]], "rank": 1, "systems": [321]}
    record = written_record(run, path, threat, _story_brief(TECHNIQUE), written)
    assert record["status"] == ScenarioStatus.BLOCKED


def test_the_gate_fails_a_threat_with_no_evidence_for_good_and_holds_back_an_outage() -> None:
    settled = {"snapshot_id": "s1", "failure": None, "attempts": [{"query": "first"}]}
    failure = evidence_problem({"evidence": [], "intel_search": settled})
    assert isinstance(failure, PathFailure) and failure.final and failure.code == ErrorCode.EVIDENCE_NOT_FOUND
    assert "2 search(es)" in failure.message
    assert isinstance(evidence_problem({"intel_search": settled | {"failure": "down"}}), Unavailable)
    assert isinstance(evidence_problem({"intel_search": None}), Unavailable)  # never searched: no snapshot
    assert evidence_problem({"evidence": [{"ref": "T0839"}], "intel_search": settled}) is None


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


def test_a_story_citing_nothing_is_final_at_once_and_asks_no_rewrite(intel: Intel, story_chat: Any) -> None:
    """The writer ignored good evidence (run 03276384: 5 such cards): the card is not finished, the path is
    given up after ONE write call, never retried five times, and no rewrite is asked for this finding."""
    answer = story_chat.responders[AiTask.WRITE_SCENARIO]
    story_chat.responders[AiTask.WRITE_SCENARIO] = lambda prompt: answer(prompt) | {
        "scenario_statement": STORY_PLAIN, "evidence_links": [],
    }  # fmt: skip
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (blocked,) = _scenarios_of(record_id)
    assert blocked["status"] == ScenarioStatus.BLOCKED
    assert FindingCode.NO_EVIDENCE_CITED in {finding["code"] for finding in blocked["findings"]}
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == 1 and not story_chat.asked(AiTask.REWRITE_SCENARIO)
    path = _sessions().find_one({"_id": record_id})["plan"]["paths"][0]
    assert path["abandoned"] and path["attempts"] == 1


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
