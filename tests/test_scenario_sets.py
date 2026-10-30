"""Writing a set of scenarios: one write and one review, then one rewrite and one review for the slots that
need them, never more than 4 AI calls; each slot read on its own, saved as soon as it is final, with its own
evidence and its threat copied back; a set too big for one call goes as halves. Fake AI models, no network."""

import dataclasses
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.core.ai_tuning_settings import AiTuningSettings
from app.core.config import get_settings
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
    _within_reask,
    blocking_codes,
    check_exact_rules,
    draft_answer,
    is_blocked,
    slot_label,
    write_set,
    writer_prompt,
    writer_system_prompt,
    written_record,
)
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import BriefSystem, PathFailure, WrittenScenario
from app.worker.scenario import path_writing
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _GROUPS, _STEP, _story_brief
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
    """Slot 3 leaves its risk statement blank, slot 5 shows no story sentence for its listed action,
    and slot 2's first review judges none of its listed actions: exactly 4 calls; the rewrite holds only SC3
    and SC5, each told its own problems, its review those two and SC2 (its draft kept as written), and slots
    1, 4 and 6 come out before the rewrite is asked."""

    def write(block: str) -> dict[str, Any]:
        answer = draft_answer(_CLEAN)
        if "REJECTED:" in block:
            return answer
        if '"Threat 3"' in block:
            return answer | {"risk_statement": " "}
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
    assert "risk_statement" in third.split("REJECTED:")[1] and _ACT in fifth.split("REJECTED:")[1]


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


@pytest.mark.usefixtures("sent", "chat")
def test_the_write_job_writes_its_set_with_its_epoch(monkeypatch: pytest.MonkeyPatch) -> None:
    """D65: a set's evidence links start where its job's epoch says, so each next set (the epoch one on)
    rotates them."""
    epochs: list[int] = []
    written = path_writing.write_set

    def spy(model: Any, briefs: Any, epoch: int = 0) -> Any:
        epochs.append(epoch)
        return written(model, briefs, epoch)

    monkeypatch.setattr(path_writing, "write_set", spy)
    record_id = _queued_run(["Threat 1"])
    _sessions().update_one({"_id": record_id}, {"$set": {"job.epoch": 4}})
    _write_batch(JobRepository(_sessions()).claim_job(record_id, 4, TaskName.WRITE_SCENARIOS, "first"))
    assert epochs == [4]


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


def test_no_story_slot_is_told_how_to_write_or_link_its_evidence_sentence() -> None:
    """D65: code writes each evidence sentence from the writer's step, so a story slot carries no evidence
    line of its own and the set note no link-variety clause; every slot is still told its own evidence."""
    briefs = [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS))]
    blocks = [block for _, block in slot_blocks(writer_prompt([(*slot, "") for slot in briefs]))]
    assert len(blocks) == 2
    assert all("EVIDENCE (untrusted data)" in block and "For this slot" not in block for block in blocks)
    system = writer_system_prompt()
    assert "links its step to its entry" not in system and "only the linking words differ" not in system


_TWO_ROUNDS = [AiTask.WRITE_SCENARIO, AiTask.PLAN_CHECK, AiTask.REPAIR_SCENARIO, AiTask.PLAN_CHECK]


#: A later use of stolen access the writer adds, which the reviewer quotes in its mismatch.
_LATER_USE = "They could then sell the stolen logins on a forum."
_MISMATCH = {
    "same_threat": False,
    "rules": {"1": f'broken: "{_LATER_USE}" - a later use of the stolen access is another threat'},
}


def _mismatch_review(block: str) -> dict[str, Any]:
    """The reviewer's mismatch quoting the added sentence when a draft has it, else a confirming review."""
    return _review_of(block) | (_MISMATCH if _LATER_USE in block else {})


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
        return _review_of(block) | {"rules": {"3": 'broken: "the stolen logins" - an invented detail'}}

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
        return _review_of(block) | (review_of if _LATER_USE in block else {})

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


def test_a_mismatch_repair_whose_step_cannot_open_codes_sentence_is_still_taken() -> None:
    """A repair clearing a mismatch is taken though its step cannot open code's sentence (code's precedent is
    cited), never the blocked first draft."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return draft_answer(_CLEAN) | {"evidence_step": f'{_STEP} like "Valid Accounts"'}
        return _with_later_use(block) | {"evidence_step": _STEP}

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


def test_a_set_too_big_for_one_call_is_sent_as_halves_each_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the most tokens one call may hold set between one slot's write and two slots', the write goes as
    two calls of one slot each, and every write and review call stays within the limit."""
    briefs = _briefs(2)
    one = max(
        call_tokens((writer_system_prompt(), writer_prompt([(label, brief, "")])), AiTask.WRITE_SCENARIO)
        for label, brief in briefs
    )
    both = writer_prompt([(label, brief, "") for label, brief in briefs])
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
    """Owner, 30 Oct (D64): no review call. Two stories, an original slot and a slot naming a made-up label:
    one write, nothing rewritten; each clean card unchecked with no warning and code's sentence from its step
    cited (D65), the label still blocked."""
    leaked = f"{_CLEAN.statement} As in SC9, it spreads."

    def write(block: str) -> dict[str, Any]:
        if '"Threat 4"' in block:
            return draft_answer(_CLEAN) | {"scenario_statement": leaked}
        return draft_answer(_CLEAN) | {"evidence_step": _STEP}

    briefs = [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS)), *_briefs(4)[2:]]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_set(fake, briefs))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO]
    blocked = outcomes.pop("SC4")
    assert isinstance(blocked, WrittenScenario) and blocking_codes(blocked) == [FindingCode.UNKNOWN_ID]
    for written in outcomes.values():
        assert isinstance(written, WrittenScenario) and written.findings == () and not written.rewritten
        assert written.plan_check.status is PlanCheckStatus.UNCHECKED
    closings = [o.draft.evidence_statement for o in outcomes.values() if isinstance(o, WrittenScenario)]
    first, second, original = closings
    step = _STEP[:1].upper() + _STEP[1:]
    assert first.startswith(f'{step} matches "Module Firmware"') and original == ""
    assert second.startswith(f'{step} mirrors "Valid Accounts"')


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


@pytest.mark.usefixtures("reviewer_off")
@pytest.mark.parametrize("fixed", [True, False], ids=["rewritten", "still_not_english"])
def test_a_slot_that_slips_out_of_english_is_written_again_and_never_served(fixed: bool) -> None:
    """Replay, 30 Oct: Kimi wrote "恢复 requires rebuilding ..." (about 1 card in 25-50, old prompt or new).
    SC2 is written again, told the words; a rewrite still not in English is a failure card, never served.
    Words the brief gives (a threat named in Arabic) and accented Latin ("naïve") are English enough: SC1 is
    kept as written."""
    slipped = f"{_CLEAN.statement} 恢复 requires rebuilding the hosts."

    def write(block: str) -> dict[str, Any]:
        if '"Threat 2"' in block and not ("REJECTED:" in block and fixed):
            return draft_answer(_CLEAN) | {"scenario_statement": slipped}
        return draft_answer(_CLEAN) | {"scenario_statement": f"{_CLEAN.statement} Its naïve default stays."}

    assert "- English only, every word of every field." in writer_system_prompt()  # told first, checked here
    briefs = [("SC1", _brief_of(_plan_threat(name="Threat مركز"))), _briefs(2)[1]]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_set(fake, briefs))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert "恢复" in fake.calls[1][1] and _labels(fake.calls[1][1]) == ["SC2"]
    assert isinstance(outcomes["SC1"], WrittenScenario) and outcomes["SC1"].findings == ()
    second = outcomes["SC2"]
    if fixed:
        assert isinstance(second, WrittenScenario) and "恢复" not in second.draft.statement
    else:
        assert isinstance(second, PathFailure) and second.code is ErrorCode.GENERATION_FAILED


def test_the_reviewer_is_off_by_default_and_in_the_config_map(monkeypatch: pytest.MonkeyPatch) -> None:
    """Owner, 30 Oct (D64): off unless CII_SCENARIO_REVIEW_ENABLED says true."""
    monkeypatch.delenv("CII_SCENARIO_REVIEW_ENABLED")
    assert AiTuningSettings(_env_file=None).scenario_review_enabled is False  # type: ignore[call-arg]
    configmap = (Path(__file__).parents[1] / "deploy" / "configmap.yaml").read_text(encoding="utf-8")
    assert 'CII_SCENARIO_REVIEW_ENABLED: "false"' in configmap
