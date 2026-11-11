"""Writing a set of scenarios: one write, then one rewrite for the slots that need it, never more than 2 AI
calls; each slot read on its own, saved as soon as it is final, with its own evidence and its threat copied
back; a set too big for one call goes as halves. Fake AI models, no network."""

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
    Status,
    TaskName,
)
from app.core.exceptions import Unavailable
from app.data_access.jobs.job_repository import JobRepository
from app.domain.scenario.write import (
    _apply_safety_checks,
    build_writer_prompt,
    build_writer_system_prompt,
    write_scenario_set,
)
from app.domain.shared.ask_ai import call_tokens
from app.models.scenario.write import BriefSystem, PathFailure, WrittenScenario
from app.worker.scenario import path_writing
from tests.external_intelligence.fakes import TECHNIQUE
from tests.external_intelligence.writing.test_evidence_story import _GROUPS, _STEP, _story_brief
from tests.fakes import FakeChatModel, draft_answer, slot_blocks, truncated
from tests.test_scenario_writing import _CLEAN, _brief_of, _plan_threat
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
            f"SC{number}",
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


def _down(_: str) -> dict[str, Any]:
    raise Unavailable("The AI service is busy.")


def test_two_bad_slots_cost_one_rewrite_and_the_good_ones_are_saved_first() -> None:
    """Slot 3 leaves its risk statement blank and slot 5 shows no story sentence for its listed action:
    exactly 2 calls; the rewrite holds only SC3 and SC5, each told its own problems, and slots 1, 2, 4 and 6
    come out before the rewrite is asked."""

    def write(block: str) -> dict[str, Any]:
        answer = draft_answer(_CLEAN)
        if "REJECTED:" in block:
            return answer
        if '"Threat 3"' in block:
            return answer | {"risk_statement": " "}
        return answer | ({"action_sentences": {}} if '"Threat 5"' in block else {})

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    calls_when_final: dict[str, int] = {}
    for label, written in write_scenario_set(fake, _briefs(6, acted={2, 5})):  # type: ignore[arg-type]
        assert isinstance(written, WrittenScenario) and written.findings == ()
        calls_when_final[label] = len(fake.calls)
    assert calls_when_final == {"SC1": 1, "SC2": 1, "SC4": 1, "SC6": 1, "SC3": 2, "SC5": 2}
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC3", "SC5"]
    third, fifth = (block for _, block in slot_blocks(rewrite))
    assert "risk_statement" in third.split("REJECTED:")[1] and _ACT in fifth.split("REJECTED:")[1]


def test_an_outage_in_the_second_round_keeps_each_usable_draft_and_retries_only_the_rest() -> None:
    """Slot 1's first answer is unreadable and slot 2's shows no story sentence for its action; the AI is
    down for their rewrite. Slot 2 keeps its first draft, and only slot 1 (no usable draft) raises the
    outage, so its path alone is retried."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            raise Unavailable("The AI service is busy.")
        if '"Threat 1"' in block:
            return {"scenario_title": "x"}
        return draft_answer(_CLEAN) | {"action_sentences": {}}

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    kept: dict[str, WrittenScenario | PathFailure] = {}
    with pytest.raises(Unavailable):
        for label, written in write_scenario_set(fake, _briefs(2, acted={2})):  # type: ignore[arg-type]
            kept[label] = written
    (second,) = kept.values()
    assert list(kept) == ["SC2"] and isinstance(second, WrittenScenario) and second.findings == ()


@pytest.mark.parametrize(
    ("first", "failed"),
    [({"scenario_title": "x"}, True), (draft_answer(_CLEAN) | {"action_sentences": {}}, False)],
    ids=["unreadable_twice", "rewrites_that_fail"],
)
def test_a_set_whose_every_slot_fails_never_takes_more_than_two_calls(
    first: dict[str, Any], failed: bool
) -> None:
    """Every slot unreadable twice: one failure card each. Every slot's rewrite still missing its action:
    each keeps its first draft. Either way no slot is asked a third time."""
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: first}
    outcomes = dict(write_scenario_set(fake, _briefs(6, acted=set(range(1, 7)))))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert len(outcomes) == 6
    if failed:
        assert {outcome.code for outcome in outcomes.values() if isinstance(outcome, PathFailure)} == {
            ErrorCode.GENERATION_FAILED
        }
    else:
        assert all(isinstance(outcome, WrittenScenario) for outcome in outcomes.values())
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
    written = path_writing.write_scenario_set

    def spy(model: Any, briefs: Any, epoch: int = 0) -> Any:
        epochs.append(epoch)
        return written(model, briefs, epoch)

    monkeypatch.setattr(path_writing, "write_scenario_set", spy)
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
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    outcomes = dict(write_scenario_set(fake, _briefs(2)))  # type: ignore[arg-type]
    assert all(isinstance(outcome, WrittenScenario) for outcome in outcomes.values())
    (rewrite,) = fake.asked(AiTask.REPAIR_SCENARIO)
    assert _labels(rewrite) == ["SC1"] and '"threat" must copy this slot' in rewrite
    brief = _briefs(1)[0][1]
    leaked = dataclasses.replace(_CLEAN, statement=_CLEAN.statement + " As in SC2, it spreads.")
    assert [finding.code for finding in _apply_safety_checks(brief, leaked).findings] == [
        FindingCode.UNKNOWN_ID
    ]


def test_each_slot_carries_its_own_evidence_or_its_own_no_evidence_line() -> None:
    """Two stories citing different entries and an original-style slot in one set: each slot of the write
    shows only its own evidence block, or the line saying none is given."""
    briefs = [
        ("SC1", _story_brief(TECHNIQUE)),
        ("SC2", _story_brief(_GROUPS)),
        ("SC3", _brief_of(_plan_threat(key="lib:3", name="Threat 3"))),
    ]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    list(write_scenario_set(fake, briefs))  # type: ignore[arg-type]
    seen: dict[AiTask, set[str]] = {}
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
    assert seen == {AiTask.WRITE_SCENARIO: {"SC1", "SC2", "SC3"}}


def test_no_story_slot_is_told_how_to_write_or_link_its_evidence_sentence() -> None:
    """D65: code writes each evidence sentence from the writer's step, so a story slot carries no evidence
    line of its own and the set note no link-variety clause; every slot is still told its own evidence."""
    briefs = [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS))]
    blocks = [block for _, block in slot_blocks(build_writer_prompt([(*slot, "") for slot in briefs])[1])]
    assert len(blocks) == 2
    assert all("EVIDENCE (untrusted data)" in block and "For this slot" not in block for block in blocks)
    system = build_writer_system_prompt()
    assert "links its step to its entry" not in system and "only the linking words differ" not in system


def test_a_faulted_slots_rewrite_an_exact_rule_blocks_leaves_its_own_draft() -> None:
    """A slot written again for a fault whose rewrite names a made-up label keeps its own unblocked draft
    instead of a blocked card."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return draft_answer(_CLEAN) | {"scenario_statement": f"{_CLEAN.statement} SYS7 helps."}
        return draft_answer(_CLEAN) | {"action_sentences": {}}

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    ((_, written),) = write_scenario_set(fake, _briefs(1, acted={1}))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert isinstance(written, WrittenScenario) and written.findings == ()
    assert written.draft.statement == _CLEAN.statement


def test_a_blocked_first_drafts_rewrite_is_kept_even_when_an_exact_rule_blocks_it_too() -> None:
    """A first draft naming a made-up label and missing a sentence number is written again: its rewrite,
    blocked by another made-up label, is kept over the blocked first draft."""
    rewritten = f"{_CLEAN.statement} SYS8 helps."

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return draft_answer(_CLEAN) | {"scenario_statement": rewritten}
        return draft_answer(_CLEAN) | {
            "scenario_statement": f"{_CLEAN.statement} SYS7 helps.",
            "action_sentences": {},
        }

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    ((_, written),) = write_scenario_set(fake, _briefs(1, acted={1}))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert isinstance(written, WrittenScenario) and written.list_blocking_codes() == [FindingCode.UNKNOWN_ID]
    assert written.draft.statement == rewritten


def test_a_slot_whose_system_reasons_name_a_system_with_html_entities_is_read_first_time() -> None:
    """Live replay, 30 Oct: the writer wrote "&amp;" for "&" in system_reasons, so a reason read as missing
    and a whole rewrite round ran for 5 slots; the name is now read with its entities."""
    name = "Enterprise Command & Control Centre Platform"
    brief = dataclasses.replace(_briefs(1)[0][1], supporting_systems=(BriefSystem(1448, name, True),))
    reason = "It could relay the attacker's commands."
    answer = draft_answer(_CLEAN) | {"system_reasons": {name.replace("&", "&amp;"): reason}}
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: answer}
    ((_, written),) = write_scenario_set(fake, [("SC1", brief)])  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO]
    assert isinstance(written, WrittenScenario) and written.draft.system_reasons == ((name, reason),)


def test_a_scenario_written_with_html_entities_is_saved_with_its_characters() -> None:
    """The card shows "Command & Control", never "Command &amp; Control"."""
    escaped = f"{_CLEAN.statement} The Command &amp; Control Centre could relay the commands."
    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN) | {"scenario_statement": escaped}
    }
    ((_, written),) = write_scenario_set(fake, _briefs(1))  # type: ignore[arg-type]
    assert isinstance(written, WrittenScenario)
    assert "Command & Control Centre" in written.draft.statement and "&amp;" not in written.draft.statement


def test_a_set_too_big_for_one_call_is_sent_as_halves_each_under_the_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the most tokens one call may hold set between one slot's write and two slots', the write goes as
    two calls of one slot each, and every write call stays within the limit."""
    briefs = _briefs(2)
    one = max(
        call_tokens(build_writer_prompt([(label, brief, "")]), AiTask.WRITE_SCENARIO)
        for label, brief in briefs
    )
    both = build_writer_prompt([(label, brief, "") for label, brief in briefs])
    assert call_tokens(both, AiTask.WRITE_SCENARIO) > one
    monkeypatch.setattr(AiLimits, "CALL_TOKENS_LIMIT", one)
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: lambda _: draft_answer(_CLEAN)}
    assert len(list(write_scenario_set(fake, briefs))) == 2  # type: ignore[arg-type]
    writes = fake.asked(AiTask.WRITE_SCENARIO)
    assert [_labels(prompt) for prompt in writes] == [["SC1"], ["SC2"]]
    for prompt in writes:
        assert call_tokens((build_writer_system_prompt(), prompt), AiTask.WRITE_SCENARIO) <= one


def test_a_clean_set_costs_one_call_and_an_exact_blocker_still_blocks() -> None:
    """Two stories, an original slot and a slot naming a made-up label: one write, nothing rewritten; each
    clean card has no warning and code's sentence from its step cited, the label still blocked."""
    leaked = f"{_CLEAN.statement} As in SC9, it spreads."

    def write(block: str) -> dict[str, Any]:
        if '"Threat 4"' in block:
            return draft_answer(_CLEAN) | {"scenario_statement": leaked}
        return draft_answer(_CLEAN) | {"evidence_step": _STEP}

    briefs = [("SC1", _story_brief(TECHNIQUE)), ("SC2", _story_brief(_GROUPS)), *_briefs(4)[2:]]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_scenario_set(fake, briefs))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO]
    blocked = outcomes.pop("SC4")
    assert isinstance(blocked, WrittenScenario) and blocked.list_blocking_codes() == [FindingCode.UNKNOWN_ID]
    for written in outcomes.values():
        assert isinstance(written, WrittenScenario) and written.findings == ()
    closings = [o.draft.evidence_statement for o in outcomes.values() if isinstance(o, WrittenScenario)]
    first, second, original = closings
    step = _STEP[:1].upper() + _STEP[1:]
    assert first == f'{step} matches the "Module Firmware" technique' and original == ""
    assert second == f'{step} mirrors the "Valid Accounts" technique'


@pytest.mark.parametrize("rewrite", [lambda _: draft_answer(_CLEAN), _down], ids=["rewritten", "outage"])
def test_a_faulted_slot_costs_one_rewrite_and_an_outage_keeps_its_draft(
    rewrite: Callable[[str], dict[str, Any]],
) -> None:
    """SC2 shows no story sentence for its listed action: one write and one rewrite. When the AI is down for
    the rewrite, SC2 keeps its own draft, with no warning."""

    def write(block: str) -> dict[str, Any]:
        if "REJECTED:" in block:
            return rewrite(block)
        return draft_answer(_CLEAN) | ({"action_sentences": {}} if '"Threat 2"' in block else {})

    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_scenario_set(fake, _briefs(2, acted={2})))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    second = outcomes["SC2"]
    assert isinstance(second, WrittenScenario) and second.findings == ()


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

    assert (
        "- English only, every word of every field." in build_writer_system_prompt()
    )  # told first, checked here
    briefs = [("SC1", _brief_of(_plan_threat(name="Threat مركز"))), _briefs(2)[1]]
    fake = FakeChatModel()
    fake.responders |= {AiTask.WRITE_SCENARIO: write}
    outcomes = dict(write_scenario_set(fake, briefs))  # type: ignore[arg-type]
    assert [task for task, _ in fake.calls] == [AiTask.WRITE_SCENARIO, AiTask.REPAIR_SCENARIO]
    assert "恢复" in fake.calls[1][1] and _labels(fake.calls[1][1]) == ["SC2"]
    assert isinstance(outcomes["SC1"], WrittenScenario) and outcomes["SC1"].findings == ()
    second = outcomes["SC2"]
    if fixed:
        assert isinstance(second, WrittenScenario) and "恢复" not in second.draft.statement
    else:
        assert isinstance(second, PathFailure) and second.code is ErrorCode.GENERATION_FAILED
