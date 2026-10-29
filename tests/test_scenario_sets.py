"""Writing a set of scenarios: one write and one review, then one rewrite and one review for the slots that
need them, never more than 4 AI calls; each slot read on its own, saved as soon as it is final, with its own
evidence and its threat copied back; a set too big for one call goes as halves. Fake AI models, no network."""

import dataclasses
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.constants import (
    AiLimits,
    AiTask,
    ErrorCode,
    FindingCode,
    PlanCheckStatus,
    ScenarioStatus,
    Status,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import (
    PLAN_CHECK_SET_PROMPT,
    check_exact_rules,
    draft_answer,
    passage_link,
    slot_label,
    write_set,
    writer_slot,
    writer_system_prompt,
    written_record,
)
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import PathFailure, WrittenScenario
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
    assert "nor the words another slot's evidence_statement links its step to its entry with" in system


@pytest.mark.parametrize(
    ("passage", "link"),
    [
        ('Altering telemetry matches the technique "Disable or Modify Tools", which X used.', "matches"),
        ('Altering telemetry resembles the related technique "Manipulate I/O Image".', "resembles"),
        ('The process behavior matches the related technique "Manipulate I/O Image".', "matches"),
        ('Abusing the operations matches "Command Message", a technique the APT28 group used.', "matches"),
        ('The opening flood is a form of "Network Denial of Service", a technique X used.', "form of"),
        ("Signing in this way corresponds to the \u201cValid Accounts\u201d technique.", "corresponds to"),
        ("Exploiting that WinCC weakness could let the attacker in, as CISA lists it exploited.", ""),
    ],
    ids=["technique", "related", "related_matches", "bare", "joiner", "curly_quotes", "no_title"],
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
_KEV_CLOSING = "Exploiting that WinCC weakness on the SCADA server could let the attacker in, as CISA lists."


def _title_of(block: str) -> str:
    return "Valid Accounts" if '"Valid Accounts"' in block else "Module Firmware"


def _story_set() -> list[tuple[str, Any]]:
    """Two story slots, each citing its own technique."""
    return [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS))]


def _write_stories(
    briefs: list[tuple[str, Any]], closing: Callable[[str], str]
) -> tuple[FakeChatModel, dict[str, WrittenScenario | PathFailure], dict[str, int]]:
    """The set written with each slot's closing sentence from `closing` (its block) and every one confirmed:
    the fake, each slot's outcome, and how many calls were made when it came out."""
    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda block: draft_answer(_CLEAN) | {"evidence_statement": closing(block)},
        AiTask.PLAN_CHECK: lambda block: _review_of(block) | {"evidence_supported": True},
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
    assert _labels(fake.asked(AiTask.PLAN_CHECK)[0]) == ["SC1"]
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC2"]
    assert 'with "matches", like another slot' in rewrite.split("REJECTED:")[1]
    first, second = outcomes["SC1"], outcomes["SC2"]
    assert isinstance(first, WrittenScenario) and isinstance(second, WrittenScenario)
    assert first.draft.evidence_statement == _MATCHES["Module Firmware"]
    assert second.draft.evidence_statement == _FORM_OF


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
