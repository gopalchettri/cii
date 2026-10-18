"""G229 (owner 2026-10-13; 2026-10-18: "Each threat scenario will have relevant one or more evidence when
EXTERNAL_INTELLIGENCE_ENABLED=true"): with external intelligence on, the write job holds back every story with
no evidence, enforced in code with no AI call added: a threat whose search kept no source at or above the
threshold fails its path for good before any write call; one whose search could not be made waits as an
outage; a story left citing nothing is kept hidden and its path tried again. The style is decided once per
delivery, and a switch in doubt makes the delivery wait. Each cited entry keeps its dates, role and claim."""

from typing import Any

import pytest

from app import container
from app.core.constants import (
    AiTask,
    Applicability,
    ErrorCode,
    ErrorMessage,
    EvidenceRole,
    FindingCode,
    Generation,
    ScenarioStatus,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.external_intelligence.intelligence_switch import IntelligenceSwitch
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import evidence_problem
from app.models.external_intelligence.evidence import Evidence
from app.models.scenario.write import PathFailure
from tests.external_intelligence.conftest import STORY_PLAIN, Intel
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.switch.test_switch import MemoryFlags
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


def test_the_gate_fails_a_threat_with_no_evidence_for_good_and_holds_back_an_outage() -> None:
    settled = {"snapshot_id": "s1", "failure": None}
    failure = evidence_problem({"evidence": [], "intel_search": settled})
    assert isinstance(failure, PathFailure) and failure.final and failure.code == ErrorCode.EVIDENCE_NOT_FOUND
    assert failure.message == ErrorMessage.EVIDENCE_NOT_FOUND
    assert isinstance(evidence_problem({"intel_search": settled | {"failure": "down"}}), Unavailable)
    assert isinstance(evidence_problem({"intel_search": None}), Unavailable)  # never searched: no snapshot
    assert evidence_problem({"evidence": [{"ref": "T0839"}], "intel_search": settled}) is None


def test_nothing_found_fails_its_path_for_good_with_no_write_call(intel: Intel, story_chat: Any) -> None:
    intel.finder.evidence = ()
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == 1
    (card,) = _scenarios_of(record_id)
    assert card["status"] == ScenarioStatus.FAILED and card["failure"]["code"] == ErrorCode.EVIDENCE_NOT_FOUND
    assert not story_chat.asked(AiTask.WRITE_SCENARIO)  # no AI call spent on a scenario that cannot be proven
    plan = _sessions().find_one({"_id": record_id})["plan"]
    assert plan["paths"][0]["abandoned"] and plan["paths"][0]["attempts"] == 1


def test_a_story_left_citing_nothing_is_kept_hidden_and_its_path_tried_again(
    intel: Intel, story_chat: Any
) -> None:
    """A story citing none of its sources is never served: each draft counts an attempt and the path is
    written again, until it is given up after MAX_PATH_ATTEMPTS."""
    answer = story_chat.responders[AiTask.WRITE_SCENARIO]

    def citing_nothing(prompt: str) -> dict[str, Any]:
        return answer(prompt) | {"scenario_statement": STORY_PLAIN, "evidence_links": []}

    story_chat.responders[AiTask.WRITE_SCENARIO] = citing_nothing
    record_id = _queued_run(["Threat 1"])
    assert _deliver_until_done(record_id) == Generation.MAX_PATH_ATTEMPTS
    (card,) = _scenarios_of(record_id)
    assert card["status"] == ScenarioStatus.BLOCKED and "controls" not in card
    assert FindingCode.NO_EVIDENCE_CITED in {finding["code"] for finding in card["findings"]}
    path = _sessions().find_one({"_id": record_id})["plan"]["paths"][0]
    assert (path["abandoned"], path["attempts"], path["served"]) == (True, Generation.MAX_PATH_ATTEMPTS, None)
    assert len(story_chat.asked(AiTask.WRITE_SCENARIO)) == Generation.MAX_PATH_ATTEMPTS


def test_the_switch_is_read_once_per_batch(intel: Intel, monkeypatch: pytest.MonkeyPatch) -> None:
    """P6: turned off while a batch runs, the batch still writes as it began (evidence stories, searched),
    never a story with no search."""
    record_id = _queued_run(["Threat 1"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "one")
    assert lease is not None
    search = intel.finder.find_evidence

    def turned_off_meanwhile(*args: Any, **kwargs: Any) -> Any:
        intel.switch.enabled = False  # an admin turns it off while the batch searches
        return search(*args, **kwargs)

    monkeypatch.setattr(container.get_evidence_finder(), "find_evidence", turned_off_meanwhile)
    _write_batch(lease)
    (scenario,) = _scenarios_of(record_id)
    assert scenario["status"] == ScenarioStatus.DONE and len(intel.finder.calls) == 1
    assert scenario["content"]["evidence"][0]["n"] == 1


def test_a_first_write_while_the_switch_cannot_be_read_waits_for_it(
    intel: Intel, story_chat: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real switch, its store unreadable and no value kept, is in doubt and reads off, so the delivery
    would write original scenarios with intelligence on. It waits instead (an outage: the job is tried again),
    with no search and no AI call."""
    flags = MemoryFlags()
    flags.down = True
    unread = IntelligenceSwitch(flags, env_enabled=lambda: True)  # type: ignore[arg-type]
    monkeypatch.setattr(container.get_intelligence_switch(), "state", unread.state)
    record_id = _queued_run(["Threat 1"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "one")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    assert _scenarios_of(record_id) == [] and intel.finder.calls == [] and story_chat.calls == []


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
