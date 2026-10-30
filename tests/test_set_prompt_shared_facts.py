"""A set's writer and reviewer calls send the facts every slot shares once, before the slots: the asset's and
each system's, by name; each slot keeps its own threat, its systems "yes" or "no" by name and any fact the
call's other slots do not share. Fake AI models, no network."""

import dataclasses
from typing import Any

from app.core.constants import ActorRole, AiTask
from app.domain.scenario.plan import planned_threat_record
from app.domain.scenario.write import (
    PLAN_CHECK_SET_PROMPT,
    build_brief,
    draft_answer,
    slot_label,
    write_set,
    writer_system_prompt,
)
from app.models.scenario.plan import PlannedActor
from app.models.scenario.write import LiveLibrary, ScenarioDraft, WriterBrief
from tests.fakes import FakeChatModel, brief_of, shared_facts, slot_blocks
from tests.planner_samples import CONTEXT, planned

#: Every sample threat ("lib:1" to "lib:6"), its type and its attacker are still in the library.
_LIVE = LiveLibrary(frozenset(range(1, 7)), frozenset({1}), frozenset({7}))
_DRAFT = ScenarioDraft(
    "Loss of control integrity",
    "A cybercriminal could push firmware to the SCADA server of Grid Control Centre.",
    "People could no longer trust the control logic of Grid Control Centre.",
    (),
    "SCADA server",
)
_REVIEW = {"rules": {"1": "holds"}, "same_threat": True, "same_impact": True}
#: Each slot's systems in turn: the SCADA server, the Historian, then both.
_PATH_SYSTEMS = ((321,), (322,), (321, 322))
#: Facts each sent once: the asset's description, the critical service and each system's technology.
_ONCE = ("Runs the transmission grid.", "Electricity transmission", "Siemens WinCC", "OSIsoft PI")


def _brief(number: int) -> WriterBrief:
    """Slot `number`'s brief: its own threat ("Threat n") on its turn's systems."""
    systems = _PATH_SYSTEMS[(number - 1) % len(_PATH_SYSTEMS)]
    actors = (PlannedActor(7, "Cybercriminal", ActorRole.ACTING),)
    threat = planned_threat_record(
        planned(f"lib:{number}", f"Threat {number}", systems=systems, actors=actors)
    )
    path = {"path_id": f"p{number}", "steps": [threat["key"]], "category": "Tampering", "systems": [*systems]}
    return build_brief({threat["key"]: threat}, path, CONTEXT, 30_000, _LIVE)


def _written(briefs: list[tuple[str, WriterBrief]], first_answer: Any = None) -> FakeChatModel:
    """The fake after `briefs` are written and reviewed; `first_answer`, when given, is the first write's."""
    fake = FakeChatModel()
    fake.responders |= {
        AiTask.WRITE_SCENARIO: lambda _: draft_answer(_DRAFT),
        AiTask.PLAN_CHECK: lambda _: _REVIEW,
    }
    if first_answer is not None:
        fake.queue(AiTask.WRITE_SCENARIO, first_answer)
    list(write_set(fake, briefs))  # type: ignore[arg-type]
    return fake


def _own_brief(block: str) -> dict[str, Any]:
    """A writer slot's BRIEF, or a reviewer slot's PLAN."""
    return brief_of(block.replace("\nPLAN:\n", "\nBRIEF:\n", 1))


def test_a_set_of_six_sends_the_asset_and_each_system_once_and_each_slot_only_its_own() -> None:
    """Measured 30 Oct: 6 slots repeated the same asset and systems facts, a quarter of the call. Now the
    write and the review each send them once, the reviewer's asset with its critical service; each slot
    still names its own threat and every system "yes" or "no", by the shared block's names."""
    briefs = [(slot_label(number), _brief(number)) for number in range(1, 7)]
    fake = _written(briefs)
    (write,), (review,) = fake.asked(AiTask.WRITE_SCENARIO), fake.asked(AiTask.PLAN_CHECK)
    for prompt in (write, review):
        assert [prompt.count(fact) for fact in _ONCE[:1] + _ONCE[2:]] == [1, 1, 1]
        asset, systems = shared_facts(prompt)
        names = [system["name"] for system in systems]
        assert asset["description"].startswith(_ONCE[0]) and names == ["SCADA server", "Historian"]
        blocks = slot_blocks(prompt)
        assert [label for label, _ in blocks] == [label for label, _ in briefs]
        for (_, block), (_, brief) in zip(blocks, briefs, strict=True):
            own = _own_brief(block)
            assert own["threat"]["threat"] == brief.threat and "asset" not in own and "systems" not in own
            yes = [system["name"] for system in own["supporting_systems"] if system["applicable"] == "yes"]
            assert yes == [system["name"] for system in brief.systems] and set(yes) <= set(names)
            assert set(own["entry_point_options"]) <= set(names)
    assert write.count(_ONCE[1]) == review.count(_ONCE[1]) == 1
    assert shared_facts(review)[0]["critical_service"] == _ONCE[1]


def test_a_fact_only_some_slots_hold_stays_in_their_own_brief() -> None:
    """A story slot reads the deployment's country and an original one does not, and a system's fact cut to
    fit one brief differs from another's: each such fact stays in its own slot's BRIEF, the rest is shared."""
    story = _brief(1)
    scada = story.systems[0] | {"technology_used": ["Windows"]}
    story = dataclasses.replace(
        story, asset=story.asset | {"country": "United Arab Emirates"}, systems=(scada,)
    )
    plain = _brief(4)  # also on the SCADA server
    (write,) = _written([("SC1", story), ("SC2", plain)]).asked(AiTask.WRITE_SCENARIO)
    asset, systems = shared_facts(write)
    assert asset == plain.asset and systems == [{k: v for k, v in scada.items() if k != "technology_used"}]
    first, second = (brief_of(block) for _, block in slot_blocks(write))
    assert first["asset"] == {"country": "United Arab Emirates"} and "asset" not in second
    assert first["systems"] == [{"name": "SCADA server", "technology_used": ["Windows"]}]
    assert second["systems"] == [{"name": "SCADA server", "technology_used": ["Windows", "Siemens WinCC"]}]


def test_a_single_slot_call_and_its_rewrite_send_every_fact_in_the_shared_block() -> None:
    """A regenerate is a set of one: its write, and its rewrite after an unreadable first answer, open with
    the asset's and its systems' facts, then its one slot with only its own fields."""
    brief = _brief(3)
    fake = _written([("SC1", brief)], first_answer={"scenario_title": "x"})
    (write,), (rewrite,) = fake.asked(AiTask.WRITE_SCENARIO), fake.asked(AiTask.REPAIR_SCENARIO)
    for prompt in (write, rewrite):
        assert shared_facts(prompt) == (brief.asset, list(brief.systems))
        ((label, block),) = slot_blocks(prompt)
        own = brief_of(block)
        assert (label, own["threat"]["threat"]) == ("SC1", brief.threat)
        assert "asset" not in own and "systems" not in own
    assert "REJECTED:" in rewrite and "REJECTED:" not in write


def test_both_set_notes_say_every_slot_reads_the_shared_facts() -> None:
    """The writer's BRIEF and the reviewer's PLAN now span the shared block and the slot: each set note says
    so, keeps a "no" system's facts out of the writer's story, and gives the reviewer the critical service."""
    writer, reviewer = writer_system_prompt(), PLAN_CHECK_SET_PROMPT
    shared = (
        'which includes ASSET and its "yes" systems\' SYSTEMS entries (its own asset or systems field adds'
    )
    assert (
        f"Each slot has its own BRIEF, {shared}" in writer
        and f"Each slot has its own PLAN, {shared}" in reviewer
    )
    assert "The user prompt opens with ASSET and SYSTEMS (by name), then one or more SLOTs" in writer
    assert "opens with ASSET (with the critical service) and SYSTEMS (by name)" in reviewer
    assert "never use a \"no\" system's facts or another slot's threat, attacker or evidence" in writer
