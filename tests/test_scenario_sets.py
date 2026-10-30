"""Writing a set of scenarios: one write and one review, then one rewrite and one review for the slots that
need them, never more than 4 AI calls; each slot read on its own, saved as soon as it is final, with its own
evidence and its threat copied back; a set too big for one call goes as halves. Fake AI models, no network."""

import dataclasses
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from structlog.testing import capture_logs

from app.core.ai_tuning_settings import AiTuningSettings
from app.core.config import get_settings
from app.core.constants import (
    AiLimits,
    AiTask,
    ErrorCode,
    FindingCode,
    LogEvent,
    PlanCheckStatus,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import (
    PLAN_CHECK_SET_PROMPT,
    _repeated_link,
    _within_reask,
    blocking_codes,
    check_exact_rules,
    draft_answer,
    is_blocked,
    passage_link,
    slot_label,
    write_set,
    writer_slot,
    writer_system_prompt,
    written_record,
)
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import BriefSystem, PathFailure, WrittenScenario
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _GROUPS, _KEV, _story_brief
from tests.fakes import FakeChatModel, brief_of, slot_blocks, truncated
from tests.planner_samples import CONTEXT
from tests.test_scenario_writing import _CLEAN, _CONSISTENT, _brief_of, _plan_threat
from tests.test_writing_job import (  # noqa: F401 - fixtures used by name
    _on_last_try,
    _queued_run,
    _scenarios_of,
    _sessions,
    _write_batch,
    chat,
    sent,
)

_ACT = "pushing firmware"


def _briefs(count: int, acted: Iterable[int] = ()) -> list[tuple[str, Any]]:
    """`count` slots, one threat each ("Threat n"), the threats in `acted` listing an action to carry out."""
    return [
        (
            slot_label(number),
            _brief_of(
                _plan_threat(
                    key=f"lib:{number}", name=f"Threat {number}", actions=[_ACT] if number in acted else []
                )
            ),
        )
        for number in range(1, count + 1)
    ]


def _labels(prompt: str) -> list[str]:
    return [label for label, _ in slot_blocks(prompt)]


def _review_of(block: str) -> dict[str, Any]:
    """A clean review, judging the listed action when the slot's PLAN lists one."""
    listed = (brief_of(block.replace("PLAN:\n", "BRIEF:\n", 1))["threat"]).get("threat_actions") or []
    return _CONSISTENT | {"threat_actions": dict.fromkeys(listed, "carried out")}


def test_two_bad_slots_cost_one_rewrite_and_one_review_and_the_good_ones_are_saved_first() -> None:
    """Slot 3 names an entry point it was not offered, slot 5 shows no story sentence for its listed action,
    and slot 2's first review judges none of its listed actions: exactly 4 calls; the rewrite holds only SC3
    and SC5, each told its own problems, its review those two and SC2 (its draft kept as written), and slots
    1, 4 and 6 come out before the rewrite is asked."""

    def write(block: str) -> dict[str, Any]:
        answer = draft_answer(_CLEAN)
        if "REJECTED:" in block:
            return answer
        if '"Threat 3"' in block:
            return answer | {"entry_point": "Engineering laptop"}
        return answer | ({"action_sentences": {}} if '"Threat 5"' in block else {})

    reviews_of_slot_2: list[str] = []

    def review(block: str) -> dict[str, Any]:
        if '"Threat 2"' in block:
            reviews_of_slot_2.append(block)
            if len(reviews_of_slot_2) == 1:  # usable, but it judges none of the listed actions
                return _review_of(block) | {"threat_actions": {}}
        return _review_of(block)

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write, AiTask.PLAN_CHECK: review}
    calls_when_final: dict[str, int] = {}
    for label, written in write_set(fake, _briefs(6, acted={2, 5})):  # type: ignore[arg-type]
        assert isinstance(written, WrittenScenario) and written.findings == ()
        calls_when_final[label] = len(fake.calls)
    assert calls_when_final == {"SC1": 2, "SC4": 2, "SC6": 2, "SC2": 4, "SC3": 4, "SC5": 4}
    tasks = [task for task, _ in fake.calls]
    assert tasks == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC3", "SC5"]
    assert _labels(fake.asked(AiTask.PLAN_CHECK)[1]) == ["SC2", "SC3", "SC5"]
    assert reviews_of_slot_2[0] == reviews_of_slot_2[1]  # the same draft reviewed again, never rewritten
    third, fifth = (block for _, block in slot_blocks(rewrite))
    assert "entry_point" in third.split("REJECTED:")[1] and _ACT in fifth.split("REJECTED:")[1]


def test_an_outage_in_the_second_round_keeps_each_usable_draft_and_retries_only_the_rest() -> None:
    """Slot 1's first answer is unreadable and slot 2's shows no story sentence for its action; the AI is
    down for their rewrite. Slot 2 keeps its first draft, flagged as not reviewed with the outage, and only
    slot 1 (no usable draft) raises the outage, so its path alone is retried."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            raise Unavailable("The AI service is busy.")
        if '"Threat 1"' in block:
            return {"scenario_title": "x"}
        return draft_answer(_CLEAN) | {"action_sentences": {}}

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write, AiTask.PLAN_CHECK: _review_of}
    kept: dict[str, WrittenScenario | PathFailure] = {}
    with pytest.raises(Unavailable):
        for label, written in write_set(fake, _briefs(2, acted={2})):  # type: ignore[arg-type]
            kept[label] = written
    (second,) = kept.values()
    assert list(kept) == ["SC2"] and isinstance(second, WrittenScenario)
    assert second.plan_check.status is PlanCheckStatus.UNCHECKED and not second.rewritten
    assert [(f.code, "The AI service is busy." in f.message) for f in second.findings] == [
        (FindingCode.PLAN_CHECK_NOT_MADE, True)
    ]


@pytest.mark.parametrize(
    ("first", "review", "calls", "failed"),
    [
        ({"scenario_title": "x"}, _CONSISTENT, [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO], True),
        (
            draft_answer(_CLEAN),
            _CONSISTENT | {"threat_actions": {_ACT: "missing"}},
            [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK],
            False,
        ),
    ],
    ids=["unreadable_twice", "repairs_that_fail"],
)
def test_a_set_whose_every_slot_fails_never_takes_more_than_four_calls(
    first: dict[str, Any], review: dict[str, Any], calls: list[AiTask], failed: bool
) -> None:
    """Every slot unreadable twice: one failure card each. Every slot's repair still missing its action:
    each keeps its first draft. Either way no slot is asked a third time."""
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: first, AiTask.PLAN_CHECK: lambda _: review}
    outcomes = dict(write_set(fake, _briefs(6, acted=set(range(1, 7)))))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == calls and len(outcomes) == 6
    if failed:
        assert {outcome.code for outcome in outcomes.values() if isinstance(outcome, PathFailure)} == {
            ErrorCode.GENERATION_FAILED
        }
    else:
        assert all(isinstance(o, WrittenScenario) and not o.rewritten for o in outcomes.values())
    assert all(len(_labels(prompt)) == 6 for _, prompt in fake.calls)


@pytest.mark.usefixtures("sent")
def test_a_set_answer_unreadable_twice_retries_the_job_and_on_its_last_try_gives_failure_cards(
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """A reply with no scenarios list, asked again once and still none: the job is given back with no card
    and nothing given up, so the whole set is written on its retry; only the job's last try gives each path
    a failure card."""
    chat.queue(AiTask.WRITE_SCENARIO, {"scenarios": "none"}, {"scenarios": "none"})
    record_id = _queued_run(["Threat 1", "Threat 2"])
    lease = JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first")
    with pytest.raises(Unavailable):
        _write_batch(lease)
    paths = _sessions().find_one({"_id": record_id})["plan"]["paths"]
    assert (
        _scenarios_of(record_id) == []
        and [(p["attempts"], p["abandoned"]) for p in paths] == [(0, False)] * 2
    )
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 2
    lease.update_job({"status": Status.QUEUED, "job.due_at": datetime.now(UTC), "job.lease_until": None})
    chat.queue(AiTask.WRITE_SCENARIO, {"scenarios": "none"}, {"scenarios": "none"})
    _write_batch(_on_last_try(record_id))
    cards = _scenarios_of(record_id)
    assert [card["failure"]["code"] for card in cards] == [ErrorCode.GENERATION_FAILED] * 2


@pytest.mark.usefixtures("sent")
def test_a_set_answer_cut_off_at_the_models_full_room_gives_failure_cards_on_the_first_try(
    chat: FakeChatModel,  # noqa: F811 - the imported fixture
) -> None:
    """At temperature 0 a retry would be cut off again, so the job is not given back: each path gets its
    failure card at once."""
    chat.queue(AiTask.WRITE_SCENARIO, truncated())
    record_id = _queued_run(["Threat 1", "Threat 2"])
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 1, TaskName.WRITE_SCENARIOS, "first"))
    cards = _scenarios_of(record_id)
    assert [card["failure"]["code"] for card in cards] == [ErrorCode.GENERATION_FAILED] * 2
    assert len(chat.asked(AiTask.WRITE_SCENARIO)) == 1


def test_a_slot_answered_with_another_slots_threat_is_written_again_and_a_slot_label_is_blocked() -> None:
    """The model answered SC1 with SC2's threat: SC1 alone is written again. A draft that names another
    slot's label (SC2) was not supplied by its brief, so it is blocked as a made-up id."""
    fake = FakeChatModel()
    swapped = draft_answer(_CLEAN) | {"threat": "Threat 2"}
    fake.queue(AiTask.WRITE_SCENARIO, swapped)
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN), AiTask.PLAN_CHECK: _review_of}
    outcomes = dict(write_set(fake, _briefs(2)))  # type: ignore[arg-type]
    assert all(isinstance(outcome, WrittenScenario) for outcome in outcomes.values())
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC1"] and '"threat" must copy this slot' in rewrite
    brief = _briefs(1)[0][1]
    leaked = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " As in SC2, it spreads.")
    assert [finding.code for finding in check_exact_rules(leaked, brief)] == [FindingCode.UNKNOWN_ID]


def test_each_slot_carries_its_own_evidence_or_its_own_no_evidence_line() -> None:
    """Two stories citing different entries and an original-style slot in one set: in every write, rewrite
    and review, each slot shows only its own evidence block, or the line saying none is given."""
    briefs = [
        ("SC1", _story_brief(TECHNIQUE)),
        ("SC2", _story_brief(_GROUPS)),
        ("SC3", _brief_of(_plan_threat(key="lib:3", name="Threat 3"))),
    ]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN), AiTask.PLAN_CHECK: _review_of}
    list(write_set(fake, briefs))  # type: ignore[arg-type]
    seen = {AiTask.WRITE_SCENARIO: set(), AiTask.PLAN_CHECK: set()}
    for task, prompt in fake.calls:
        for label, block in slot_blocks(prompt):
            seen.setdefault(task, set()).add(label)
            own = {"SC1": "Module Firmware", "SC2": "Valid Accounts"}.get(label)
            others = {"Module Firmware", "Valid Accounts"} - {own}
            assert block.count("EVIDENCE (untrusted data)") == (1 if own else 0), (task, label)
            assert (own is None or own in block) and not any(other in block for other in others), (
                task,
                label,
            )
            assert ("No EVIDENCE is given for this slot" in block) is (own is None), (task, label)
    assert seen[AiTask.WRITE_SCENARIO] == seen[AiTask.PLAN_CHECK] == {"SC1", "SC2", "SC3"}


def test_each_story_slot_repeats_the_evidence_rule_with_its_own_cited_title() -> None:
    """Laptop e2e, 29 Oct: in a set the writer dropped the evidence rule (no quoted title, or no sentence) in
    13 of 13 first drafts, each costing a rewrite. A story slot now says it beside its own evidence, with its
    own title and in words no other slot uses; an original-style slot does not. Laptop e2e, 30 Oct: all 10
    closing sentences copied the system prompt's made-up example, so it shows none."""
    briefs = [
        ("SC1", _story_brief(TECHNIQUE)),
        ("SC2", _story_brief(_GROUPS)),
        ("SC3", _brief_of(_plan_threat(key="lib:3", name="Threat 3"))),
    ]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN), AiTask.PLAN_CHECK: _review_of}
    list(write_set(fake, briefs))  # type: ignore[arg-type]
    write = next(prompt for task, prompt in fake.calls if task == AiTask.WRITE_SCENARIO)
    blocks = dict(slot_blocks(write))
    rule = "For this slot, evidence_statement is ONE sentence"
    assert '"Module Firmware" in double quotes' in blocks["SC1"] and rule in blocks["SC1"]
    assert '"Valid Accounts" in double quotes' in blocks["SC2"] and "Module Firmware" not in blocks["SC2"]
    assert rule not in blocks["SC3"]
    assert all("in words no other slot uses" in blocks[label] for label in ("SC1", "SC2"))
    system = writer_system_prompt()
    assert "made-up example" not in system and "matches the technique" not in system
    assert "nor how another slot's evidence_statement links its step to its entry" in system
    # laptop e2e, 30 Oct: 8 of 13 sentences paraphrased their system, 5 ended "a technique used by"
    assert all("naming its system or asset as BRIEF does" in blocks[label] for label in ("SC1", "SC2"))
    # review, 30 Oct: two slots citing one group could not both copy used_by (rule 10) and name it in words
    # no other slot uses; only the linking words differ, the names are always copied
    assert "(who used it is copied exactly from used_by: only the linking words differ)" in system
    assert "where it reads best, copy who used it exactly from used_by" in blocks["SC1"]
    assert "name who used it (from used_by)" not in blocks["SC1"] and "names who used it" not in system


@pytest.mark.parametrize(
    ("passage", "link"),
    [
        ('Altering telemetry matches the technique "Disable or Modify Tools", which X used.', "matches"),
        ('Altering telemetry resembles the related technique "Manipulate I/O Image".', "resembles"),
        ('The process behavior matches the related technique "Manipulate I/O Image".', "matches"),
        ('Abusing the operations matches "Command Message", a technique the APT28 group used.', "matches"),
        ('The opening flood is a form of "Network Denial of Service", a technique X used.', "form of"),
        ("Signing in this way corresponds to the \u201cValid Accounts\u201d technique.", "corresponds to"),
        ('Flooding the gateway falls under "Network Denial of Service".', "falls under"),
        ("Exploiting that WinCC weakness could let the attacker in, as CISA lists it exploited.", ""),
    ],
    ids=["technique", "related", "related_matches", "bare", "joiner", "curly_quotes", "under", "no_title"],
)
def test_passage_link(passage: str, link: str) -> None:
    """The words a closing sentence links its step to its title with: the last word before the title (two
    after a joiner), "the", "technique" and "related" aside; none without a quoted title."""
    assert passage_link(passage) == link


#: Each cited title's closing sentence, both linking with "matches" (laptop e2e, 30 Oct: 10 of 10 did).
_MATCHES = {
    "Module Firmware": (
        'Pushing rogue firmware to the SCADA server matches the technique "Module Firmware", which the '
        "Sandworm Team group has used."
    ),
    "Valid Accounts": (
        'Signing in to the SCADA server with the maintenance login matches the technique "Valid Accounts", '
        "which the APT41 and FIN8 groups have used."
    ),
}
_FORM_OF = (
    'Signing in to the SCADA server with the maintenance login is a form of "Valid Accounts", a technique '
    "the APT41 and FIN8 groups have used."
)
#: A rewrite's closing sentence code cannot cite (it says "documented").
_DOCUMENTED = _FORM_OF.replace("a technique the APT41 and FIN8 groups have used", "as documented")
_KEV_CLOSING = "Exploiting that WinCC weakness on the SCADA server could let the attacker in, as CISA lists."


def _title_of(block: str) -> str:
    return "Valid Accounts" if '"Valid Accounts"' in block else "Module Firmware"


def _story_set() -> list[tuple[str, Any]]:
    """Two story slots, each citing its own technique."""
    return [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS))]


def _confirmed(block: str) -> dict[str, Any]:
    """A clean review confirming the closing sentence."""
    return _review_of(block) | {"evidence_supported": True}


def _write_stories(
    briefs: list[tuple[str, Any]], closing: Callable[[str], str], reviews: Iterable[Any] = ()
) -> tuple[FakeChatModel, dict[str, WrittenScenario | PathFailure], dict[str, int]]:
    """The set written with each slot's closing sentence from `closing` (its block) and every one confirmed,
    but for the slots answered first by the queued `reviews`: the fake, each slot's outcome, and how many
    calls were made when it came out."""
    fake = FakeChatModel()
    fake.queue(AiTask.PLAN_CHECK, *reviews)
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda block: draft_answer(_CLEAN) | {"evidence_statement": closing(block)},
        AiTask.PLAN_CHECK: _confirmed,
    }
    outcomes: dict[str, WrittenScenario | PathFailure] = {}
    calls_when_final: dict[str, int] = {}
    for label, written in write_set(fake, briefs):  # type: ignore[arg-type]
        outcomes[label], calls_when_final[label] = written, len(fake.calls)
    return fake, outcomes, calls_when_final


_TWO_ROUNDS = [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]


def test_a_story_slot_linking_like_an_earlier_slot_is_written_again() -> None:
    """Laptop e2e, 30 Oct: every closing sentence of a set linked with "matches the technique". SC2, linking
    like SC1, is written again in the set's one rewrite, told the link taken; SC1 keeps its words and comes
    out after the first round."""
    fake, outcomes, calls_when_final = _write_stories(
        _story_set(), lambda block: _FORM_OF if "REJECTED:" in block else _MATCHES[_title_of(block)]
    )
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS and calls_when_final == {"SC1": 2, "SC2": 4}
    assert _labels(fake.asked(AiTask.PLAN_CHECK)[0]) == ["SC1", "SC2"]  # SC2's draft is kept if need be
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC2"]
    assert 'with "matches the technique" like another slot' in rewrite.split("REJECTED:")[1]  # its own words
    first, second = outcomes["SC1"], outcomes["SC2"]
    assert isinstance(first, WrittenScenario) and isinstance(second, WrittenScenario)
    assert first.draft.evidence_statement == _MATCHES["Module Firmware"]
    assert second.draft.evidence_statement == _FORM_OF and second.rewritten and second.findings == ()


@pytest.mark.parametrize(
    ("briefs", "closing"),
    [
        (_story_set, lambda block: _FORM_OF if '"Valid Accounts"' in block else _MATCHES["Module Firmware"]),
        (lambda: [("SC1", _story_brief(_KEV)), ("SC2", _story_brief(_KEV))], lambda _: _KEV_CLOSING),
    ],
    ids=["different_links", "no_quoted_title"],
)
def test_story_slots_linking_in_their_own_words_or_with_no_title_are_not_written_again(
    briefs: Callable[[], list[tuple[str, Any]]], closing: Callable[[str], str]
) -> None:
    """Two links of their own, or two sentences tied to a vulnerability's facts (no quoted title, so no link
    to compare): one write and one review, every sentence cited."""
    fake, outcomes, _ = _write_stories(briefs(), closing)
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    assert all(isinstance(o, WrittenScenario) and o.findings == () for o in outcomes.values())


def test_a_slot_written_again_for_another_fault_claims_no_link() -> None:
    """SC1's closing sentence says "documented", so it is written again anyway: its draft, about to be
    replaced, never sends SC2 (linking like it) to the rewrite."""
    users = "which the Sandworm Team group has used"
    documented = _MATCHES["Module Firmware"].replace(users, "as documented")

    def closing(block: str) -> str:
        if _title_of(block) == "Valid Accounts":
            return _MATCHES["Valid Accounts"]
        return _MATCHES["Module Firmware"] if "REJECTED:" in block else documented

    fake, outcomes, _ = _write_stories(_story_set(), closing)
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS and _labels(rewrite) == ["SC1"]
    assert '"documented"' in rewrite and "like another slot" not in rewrite
    assert all(isinstance(o, WrittenScenario) and o.findings == () for o in outcomes.values())


def test_a_rewrite_that_still_links_like_another_slot_is_cited_as_written() -> None:
    """The guard asks once and never refuses: SC2's rewrite still links with "matches" and is cited as the
    writer wrote it, never replaced by code's own sentence (no CITATION_REMOVED) and never blocked."""
    fake, outcomes, _ = _write_stories(_story_set(), lambda block: _MATCHES[_title_of(block)])
    second = outcomes["SC2"]
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS and isinstance(second, WrittenScenario)
    threat = _plan_threat(evidence=[_GROUPS.as_doc()], intel_search={"query": "q"})
    run = {"_id": "r1", "entity_id": 86, "asset_id": 5, "context": {"systems": CONTEXT.systems}}
    path = {"path_id": "p1", "category": "Tampering", "steps": [threat["key"]], "systems": [321]}
    record = written_record(run, path, threat, _story_set()[1][1], second)
    assert record["status"] == ScenarioStatus.DONE and record["findings"] == []
    assert record["content"]["statement"].endswith(f"{_MATCHES['Valid Accounts'].removesuffix('.')} [1].")


def _busy() -> str:
    raise Unavailable("The AI service is busy.")


@pytest.mark.parametrize(
    "rewrite",
    [lambda: _DOCUMENTED, _busy],
    ids=["rewrite_not_citable", "outage"],
)
def test_a_relinked_slot_keeps_its_reviewed_cited_draft_when_its_rewrite_does_worse(
    rewrite: Callable[[], str],
) -> None:
    """Review, 30 Oct: SC2 was clean but for its repeated link, yet a rewrite saying "documented", or an
    outage in the second round, cost it its own sentence (code's cited instead). SC2 is now reviewed with
    SC1 in the first round, so its reviewed, cited first draft stays."""
    fake, outcomes, _ = _write_stories(
        _story_set(), lambda block: rewrite() if "REJECTED:" in block else _MATCHES[_title_of(block)]
    )
    assert _labels(fake.asked(AiTask.PLAN_CHECK)[0]) == ["SC1", "SC2"]
    second = outcomes["SC2"]
    assert isinstance(second, WrittenScenario) and second.findings == () and not second.rewritten
    assert second.plan_check.status is PlanCheckStatus.CONSISTENT
    assert second.draft.evidence_statement == _MATCHES["Valid Accounts"]


_UNUSABLE = {"rules": "?"}  # a review answer no reader can use


@pytest.mark.parametrize(
    ("second_review", "status", "findings"),
    [
        (_confirmed, PlanCheckStatus.CONSISTENT, []),
        (
            _UNUSABLE,
            PlanCheckStatus.UNCHECKED,
            [FindingCode.PLAN_CHECK_NOT_MADE, FindingCode.CITATION_REMOVED],
        ),
    ],
    ids=["reviewed", "review_unusable_again"],
)
def test_a_relinked_slot_whose_review_is_asked_again_is_reviewed_again_never_rewritten(
    second_review: Any, status: PlanCheckStatus, findings: list[FindingCode]
) -> None:
    """Final review, 30 Oct: SC2 links like SC1 and its first review is unusable, so it has no reviewed draft
    to fall back on. It is not rewritten (a clean draft is never risked for variety): its own draft is
    reviewed again and saved, its repeated link cited when that review confirms it (D60)."""
    fake, outcomes, _ = _write_stories(
        _story_set(), lambda block: _MATCHES[_title_of(block)], reviews=(_confirmed, _UNUSABLE, second_review)
    )
    second = outcomes["SC2"]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.PLAN_CHECK]
    assert _labels(fake.asked(AiTask.PLAN_CHECK)[1]) == ["SC2"]
    assert isinstance(second, WrittenScenario) and not second.rewritten
    assert second.draft.statement == draft_answer(_CLEAN)["scenario_statement"]
    assert second.plan_check.status is status and [finding.code for finding in second.findings] == findings
    assert second.draft.evidence_statement == ("" if findings else _MATCHES["Valid Accounts"])


_HIDE = "hiding the change"


def _relinked_acting_slot(first_review: dict[str, Any]) -> tuple[str, WrittenScenario | PathFailure]:
    """SC2 lists two actions and links like SC1, its first review `first_review`; its rewrite carries out
    both but says "documented": SC2's rewrite prompt and its outcome."""
    acting = dataclasses.replace(_story_brief(_GROUPS), threat_actions=(_ACT, _HIDE))
    fake, outcomes, _ = _write_stories(
        [("SC1", _story_brief(TECHNIQUE)), ("SC2", acting)],
        lambda block: _DOCUMENTED if "REJECTED:" in block else _MATCHES[_title_of(block)],
        reviews=(_confirmed, _CONSISTENT | {"evidence_supported": True} | first_review),
    )
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS and _labels(rewrite) == ["SC2"]
    return rewrite, outcomes["SC2"]


def test_a_relinked_slot_whose_consistent_review_left_an_action_unjudged_is_told_only_its_link() -> None:
    """Review, 30 Oct: a consistent review judging one of SC2's two listed actions left the other "not
    carried out", so SC2's relink was told to repair it and, its link no longer the only ask, a rewrite whose
    sentence cannot be cited replaced its reviewed, cited first draft. Only an inconsistent review repairs."""
    rewrite, second = _relinked_acting_slot({"threat_actions": {_ACT: "carried out"}})
    assert "REVIEW:" not in rewrite and "like another slot" in rewrite.split("REJECTED:")[1]
    assert isinstance(second, WrittenScenario) and second.findings == () and not second.rewritten
    assert second.plan_check.status is PlanCheckStatus.CONSISTENT
    assert second.draft.evidence_statement == _MATCHES["Valid Accounts"]


def test_a_relinked_slot_with_an_action_to_repair_is_told_both_and_its_repair_is_kept() -> None:
    """SC2 links like SC1 and its review finds a listed action not carried out: its rewrite is told both,
    the action then the link, and a repair carrying the action out is kept though its sentence cannot be
    cited (code's own is): the link was not the only ask."""
    rewrite, second = _relinked_acting_slot({"threat_actions": {_ACT: "carried out", _HIDE: "missing"}})
    review, rejected = rewrite.split("REVIEW:")[1].split("REJECTED:")
    assert f'were not carried out: "{_HIDE}".' in review and "like another slot" in rejected
    assert isinstance(second, WrittenScenario) and second.rewritten
    assert second.plan_check.status is PlanCheckStatus.CONSISTENT and second.draft.evidence_statement == ""
    assert [finding.code for finding in second.findings] == [FindingCode.CITATION_REMOVED]


def test_a_relinks_citable_rewrite_is_taken_though_its_consistent_review_leaves_an_action_unjudged() -> None:
    """Final review, 30 Oct: SC2 lists two actions and links like SC1; both its reviews are consistent and
    judge only one. Its rewrite, citable and linking in its own words, was refused for the action left
    unjudged, which a consistent review never repairs (_listed_actions): it is now taken."""
    acting = dataclasses.replace(_story_brief(_GROUPS), threat_actions=(_ACT, _HIDE))
    one_judged = _CONSISTENT | {"evidence_supported": True, "threat_actions": {_ACT: "carried out"}}
    fake, outcomes, _ = _write_stories(
        [("SC1", _story_brief(TECHNIQUE)), ("SC2", acting)],
        lambda block: _FORM_OF if "REJECTED:" in block else _MATCHES[_title_of(block)],
        reviews=(_confirmed, one_judged, one_judged),
    )
    second = outcomes["SC2"]
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS
    assert isinstance(second, WrittenScenario) and second.rewritten and second.findings == ()
    assert second.plan_check.status is PlanCheckStatus.CONSISTENT
    assert second.plan_check.actions_not_carried_out == (_HIDE,)
    assert second.draft.evidence_statement == _FORM_OF


def test_a_blocked_slot_claims_no_link() -> None:
    """Review, 30 Oct: a slot an exact finding blocks is final in the first round as a blocked card, so its
    link never sends a clean slot linking like it to a rewrite."""

    def write(block: str) -> dict[str, Any]:
        answer = draft_answer(_CLEAN) | {"evidence_statement": _MATCHES[_title_of(block)]}
        leaked = f"{answer['scenario_statement']} As in SC9, it spreads."
        return answer | ({"scenario_statement": leaked} if _title_of(block) == "Module Firmware" else {})

    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: write,
        AiTask.PLAN_CHECK: lambda block: _review_of(block) | {"evidence_supported": True},
    }
    outcomes = dict(write_set(fake, _story_set()))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    first, second = outcomes["SC1"], outcomes["SC2"]
    assert isinstance(first, WrittenScenario) and is_blocked(first)
    assert isinstance(second, WrittenScenario) and second.findings == ()


#: A later use of stolen access the writer adds, which the reviewer quotes in its mismatch.
_LATER_USE = "They could then sell the stolen logins on a forum."
_MISMATCH = {
    "same_threat": False,
    "rules": {"1": f'broken: "{_LATER_USE}" - a later use of the stolen access is another threat'},
}


def _mismatch_review(block: str) -> dict[str, Any]:
    """The reviewer's mismatch quoting the added sentence when a draft has it, else a confirming review."""
    return _confirmed(block) | (_MISMATCH if _LATER_USE in block else {})


def _with_later_use(_: str) -> dict[str, Any]:
    """A draft adding the later use of stolen access."""
    return draft_answer(_CLEAN) | {"scenario_statement": f"{_CLEAN.statement} {_LATER_USE}"}


def _down(_: str) -> dict[str, Any]:
    raise Unavailable("The AI service is busy.")


def _write_mismatched(
    rewrite: Callable[[str], dict[str, Any]],
) -> tuple[FakeChatModel, dict[str, WrittenScenario | PathFailure]]:
    """SC1 clean, SC2's first draft adding the later use and its rewrite answered by `rewrite`: the fake and
    each slot's outcome."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return rewrite(block)
        return _with_later_use(block) if '"Threat 2"' in block else draft_answer(_CLEAN)

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write, AiTask.PLAN_CHECK: _mismatch_review}
    return fake, dict(write_set(fake, _briefs(2)))  # type: ignore[arg-type]


def _record_of(written: WrittenScenario | PathFailure) -> dict[str, Any]:
    """The card SC2's outcome is saved as."""
    assert isinstance(written, WrittenScenario)
    threat = _plan_threat(key="lib:2", name="Threat 2")
    run = {"_id": "r1", "entity_id": 86, "asset_id": 5, "context": {"systems": CONTEXT.systems}}
    path = {"path_id": "p2", "category": "Tampering", "steps": [threat["key"]], "systems": [321]}
    return written_record(run, path, threat, _briefs(2)[1][1], written)


def test_a_mismatched_draft_is_repaired_in_round_2_told_the_reviewers_quoted_words() -> None:
    """Owner, 30 Oct: the reviewer blocked 3 of 15 scenarios as mismatched, each giving its path up for a
    reserve written in a new batch. SC2 is now rewritten in the set's one rewrite, told the mismatch and the
    reviewer's quoted words, and its fixed rewrite is saved done; SC1 comes out after the first round."""
    fake, outcomes = _write_mismatched(lambda _: draft_answer(_CLEAN))
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    told = rewrite.split("REJECTED:")[1]
    assert _labels(rewrite) == ["SC2"] and "no longer describes the plan's threat" in told
    assert f'Rule 1: "{_LATER_USE}" - a later use' in told
    second = outcomes["SC2"]
    assert isinstance(second, WrittenScenario) and second.rewritten and second.findings == ()
    record = _record_of(second)
    assert record["status"] == ScenarioStatus.DONE and record["rewritten"] is True


@pytest.mark.parametrize(
    ("rewrite", "calls"),
    [(_with_later_use, _TWO_ROUNDS), (_down, _TWO_ROUNDS[:3])],
    ids=["still_mismatched", "outage"],
)
def test_a_mismatch_repair_that_fails_keeps_the_blocked_first_draft(
    rewrite: Callable[[str], dict[str, Any]], calls: list[AiTask]
) -> None:
    """A repair still mismatched, or an outage at the round-2 rewrite: SC2's blocked first draft is yielded
    as before, so its path is given up and a reserve still follows."""
    fake, outcomes = _write_mismatched(rewrite)
    second = outcomes["SC2"]
    assert [task for task, _ in fake.calls] == calls
    assert isinstance(second, WrittenScenario) and not second.rewritten
    assert _LATER_USE in second.draft.statement and _record_of(second)["status"] == ScenarioStatus.BLOCKED


def test_a_mismatch_repair_breaking_another_rule_is_taken_over_the_blocked_first_draft() -> None:
    """Review, 30 Oct: a repair clearing the mismatch was thrown away for one rule its first draft held,
    so the blocked draft was saved and a reserve written; a reviewed repair nothing blocks is taken."""

    def review(block: str) -> dict[str, Any]:
        if _LATER_USE in block:
            return _mismatch_review(block)
        return _confirmed(block) | {"rules": {"3": 'broken: "the stolen logins" - an invented detail'}}

    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda block: (
            draft_answer(_CLEAN) if "REJECTED:" in block else _with_later_use(block)
        ),
        AiTask.PLAN_CHECK: review,
    }
    ((_, written),) = write_set(fake, _briefs(1))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS
    assert isinstance(written, WrittenScenario) and written.rewritten and not is_blocked(written)


def test_a_mismatch_rewrite_is_told_the_reviewers_whole_reason_and_most_of_its_quote() -> None:
    """Review, 30 Oct: the reviewer's problem was cut at 300 characters before the note shortened its quote,
    so a 217-character quote lost its reason ("...than the plan's cr…")."""
    quote = f"{_LATER_USE} " + " ".join(
        ["They could also reuse the session on every connected workstation."] * 3
    )
    reason = "This adds a later use of the stolen access, which is a different threat than the plan's one."
    review_of = {"same_threat": False, "rules": {"1": f'broken: "{quote}" - {reason}'}}

    def review(block: str) -> dict[str, Any]:
        return _confirmed(block) | (review_of if _LATER_USE in block else {})

    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda block: (
            draft_answer(_CLEAN) if "REJECTED:" in block else _with_later_use(block)
        ),
        AiTask.PLAN_CHECK: review,
    }
    list(write_set(fake, _briefs(1)))  # type: ignore[arg-type]
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    told = rewrite.split("REJECTED:")[1]
    assert f"- {reason}" in told
    shown_quote = told.split('Rule 1: "')[1].split('…"')[0]
    assert len(shown_quote) > 150  # a mismatch keeps a stored problem's size, not a re-ask's 200


def test_a_reviewers_long_quote_is_shortened_in_the_rewrite_note_and_its_reason_kept_whole() -> None:
    """Live replay, 30 Oct: the note cut the reviewer's reason mid-word ("This adds a p")."""
    quote = " ".join(["the attacker could then pivot to the Intelligent Traffic Systems Platform"] * 4)
    reason = " - This adds a pivot and an exfiltration the threat's name does not state."
    shown = _within_reask(f'Rule 1: "{quote}"{reason}')
    assert len(shown) <= AiLimits.REASK_PROBLEM_CHARS and shown.endswith(reason)
    assert shown.startswith('Rule 1: "the attacker could then pivot') and '…"' in shown


def test_a_mismatch_repair_whose_evidence_sentence_cannot_be_cited_is_still_taken() -> None:
    """Keeping a cited sentence guards a link-only relink: a repair clearing a mismatch is taken though its
    sentence cannot be cited (code's own is), never the blocked first draft."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return draft_answer(_CLEAN) | {"evidence_statement": _DOCUMENTED}
        return _with_later_use(block) | {"evidence_statement": _MATCHES["Valid Accounts"]}

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write, AiTask.PLAN_CHECK: _mismatch_review}
    ((_, written),) = write_set(fake, [("SC1", _story_brief(_GROUPS))])  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS
    assert isinstance(written, WrittenScenario) and written.rewritten and not is_blocked(written)
    assert [finding.code for finding in written.findings] == [FindingCode.CITATION_REMOVED]
    assert written.draft.evidence_statement == ""


def test_a_repair_whose_review_must_be_asked_again_keeps_the_first_draft() -> None:
    """A repair whose round-2 review judges none of the listed actions has a review to ask again, so it is
    not proven fixed: the reviewed first draft stays."""
    fake = FakeChatModel()
    fake.queue(AiTask.PLAN_CHECK, _CONSISTENT | {"threat_actions": {_ACT: "missing"}}, _CONSISTENT)
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    ((_, written),) = write_set(fake, _briefs(1, acted={1}))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == _TWO_ROUNDS
    assert isinstance(written, WrittenScenario) and not written.rewritten
    assert written.plan_check.actions_not_carried_out == (_ACT,)


def test_a_faulted_slots_rewrite_an_exact_rule_blocks_leaves_its_own_draft_to_be_reviewed() -> None:
    """A slot written again for a fault whose rewrite names a made-up label keeps its own unblocked draft,
    reviewed in round 2, instead of a blocked card."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return draft_answer(_CLEAN) | {"scenario_statement": f"{_CLEAN.statement} SYS7 helps."}
        return draft_answer(_CLEAN) | {"action_sentences": {}}

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write, AiTask.PLAN_CHECK: _review_of}
    ((_, written),) = write_set(fake, _briefs(1, acted={1}))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [_TWO_ROUNDS[0], *_TWO_ROUNDS[2:]]  # no first review
    assert isinstance(written, WrittenScenario) and written.findings == ()
    assert written.draft.statement == _CLEAN.statement
    assert written.plan_check.status is PlanCheckStatus.CONSISTENT


def test_a_slot_whose_system_reasons_name_a_system_with_html_entities_is_read_first_time() -> None:
    """Live replay, 30 Oct: the writer wrote "&amp;" for "&" in system_reasons, so a reason read as missing
    and a whole rewrite round ran for 5 slots; the name is now read with its entities."""
    name = "Enterprise Command & Control Centre Platform"
    brief = dataclasses.replace(_briefs(1)[0][1], supporting_systems=(BriefSystem(1448, name, True),))
    reason = "It could relay the attacker's commands."
    answer = draft_answer(_CLEAN) | {"system_reasons": {name.replace("&", "&amp;"): reason}}
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: answer, AiTask.PLAN_CHECK: _review_of}
    ((_, written),) = write_set(fake, [("SC1", brief)])  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK]
    assert isinstance(written, WrittenScenario) and written.draft.system_reasons == ((name, reason),)


def test_a_scenario_written_with_html_entities_is_saved_with_its_characters() -> None:
    """The card shows "Command & Control", never "Command &amp; Control"."""
    escaped = f"{_CLEAN.statement} The Command &amp; Control Centre could relay the commands."
    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN) | {"scenario_statement": escaped},
        AiTask.PLAN_CHECK: _review_of,
    }
    ((_, written),) = write_set(fake, _briefs(1))  # type: ignore[arg-type]
    assert isinstance(written, WrittenScenario)
    assert "Command & Control Centre" in written.draft.statement and "&amp;" not in written.draft.statement


def test_a_repeated_links_note_lists_only_the_whole_taken_links_that_fit_a_reask_problem() -> None:
    """Review, 30 Oct: with 6 or more links taken the list ran past a re-ask problem's 200 characters and
    was cut mid-link; it now lists only the whole links that fit."""
    used = [f"link words number {number}" for number in range(13)]
    note = _repeated_link("matches the technique", used)
    listed = note.split("(taken: ")[1].removesuffix(")").split(", ")
    assert len(note) <= AiLimits.REASK_PROBLEM_CHARS and listed[0] == f'"{used[0]}"'
    assert all(link.strip('"') in used for link in listed)


def test_a_set_too_big_for_one_call_is_sent_as_halves_each_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the most tokens one call may hold set between one slot's write and two slots', the write goes as
    two calls of one slot each, and every write and review call stays within the limit."""
    briefs = _briefs(2)
    one = max(
        call_tokens((writer_system_prompt(), writer_slot(label, brief)), AiTask.WRITE_SCENARIO)
        for label, brief in briefs
    )
    both = "\n\n".join(writer_slot(label, brief) for label, brief in briefs)
    assert call_tokens((writer_system_prompt(), both), AiTask.WRITE_SCENARIO) > one
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", one)
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN), AiTask.PLAN_CHECK: _review_of}
    assert len(list(write_set(fake, briefs))) == 2  # type: ignore[arg-type]
    writes, reviews = fake.asked(AiTask.WRITE_SCENARIO), fake.asked(AiTask.PLAN_CHECK)
    assert [_labels(prompt) for prompt in writes] == [["SC1"], ["SC2"]]
    for prompt in writes:
        assert call_tokens((writer_system_prompt(), prompt), AiTask.WRITE_SCENARIO) <= one
    for prompt in reviews:
        assert call_tokens((PLAN_CHECK_SET_PROMPT, prompt), AiTask.PLAN_CHECK) <= one


@pytest.fixture
def reviewer_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """The AI reviewer off, its default (D64); the rest of the suite runs it on (tests/conftest.py)."""
    monkeypatch.setattr(get_settings(), "scenario_review_enabled", False)


@pytest.mark.usefixtures("reviewer_off")
def test_with_the_reviewer_off_a_clean_set_costs_one_call_and_an_exact_blocker_still_blocks() -> None:
    """Owner, 30 Oct (D64): no review call. Two stories linking alike, an original slot and a slot naming a
    made-up label: one write, nothing rewritten (the repeated link only logged: a rewrite could not be judged
    better); each clean card unchecked with no warning and its own passage cited, the label still blocked."""
    leaked = f"{_CLEAN.statement} As in SC9, it spreads."

    def write(block: str) -> dict[str, Any]:
        if '"Threat 4"' in block:
            return draft_answer(_CLEAN) | {"scenario_statement": leaked}
        closing = {"evidence_statement": _MATCHES[_title_of(block)]} if "EVIDENCE (untrusted" in block else {}
        return draft_answer(_CLEAN) | closing

    briefs = [*_story_set(), *_briefs(4)[2:]]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    with capture_logs() as logs:
        outcomes = dict(write_set(fake, briefs))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO]
    assert [log["slots"] for log in logs if log["event"] == LogEvent.WRITER_LINKS_REPEATED] == [1]
    blocked = outcomes.pop("SC4")
    assert isinstance(blocked, WrittenScenario) and blocking_codes(blocked) == [FindingCode.UNKNOWN_ID]
    for written in outcomes.values():
        assert isinstance(written, WrittenScenario) and written.findings == () and not written.rewritten
        assert written.plan_check.status is PlanCheckStatus.UNCHECKED
    closings = [o.draft.evidence_statement for o in outcomes.values() if isinstance(o, WrittenScenario)]
    assert closings == [_MATCHES["Module Firmware"], _MATCHES["Valid Accounts"], ""]


@pytest.mark.usefixtures("reviewer_off")
@pytest.mark.parametrize("rewrite", [lambda _: draft_answer(_CLEAN), _down], ids=["rewritten", "outage"])
def test_with_the_reviewer_off_a_faulted_slot_costs_one_rewrite_and_an_outage_keeps_its_draft(
    rewrite: Callable[[str], dict[str, Any]],
) -> None:
    """SC2 shows no story sentence for its listed action: one write and one rewrite, never a review. When
    the AI is down for the rewrite, SC2 keeps its own draft, unchecked with no warning (no review was due)."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return rewrite(block)
        return draft_answer(_CLEAN) | ({"action_sentences": {}} if '"Threat 2"' in block else {})

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_set(fake, _briefs(2, acted={2})))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    second = outcomes["SC2"]
    assert isinstance(second, WrittenScenario) and second.findings == ()
    assert second.plan_check.status is PlanCheckStatus.UNCHECKED and not second.rewritten


def test_the_reviewer_is_off_by_default_and_in_the_config_map(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner, 30 Oct (D64): off unless CII_SCENARIO_REVIEW_ENABLED says true."""
    monkeypatch.delenv("CII_SCENARIO_REVIEW_ENABLED")
    assert AiTuningSettings(_env_file=None).scenario_review_enabled is False  # type: ignore[call-arg]
    configmap = (Path(__file__).parents[1] / "deploy" / "configmap.yaml").read_text(encoding="utf-8")
    assert 'CII_SCENARIO_REVIEW_ENABLED: "false"' in configmap
