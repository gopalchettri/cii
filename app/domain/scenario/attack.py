"""An attack run's writer rules: its plan, the answer checked against MITRE ATT&CK in MongoDB, and the card."""

import dataclasses
import json
import re
from collections.abc import Collection, Iterable, Sequence
from datetime import datetime
from functools import partial
from typing import Any, Final

from pydantic import BaseModel, field_validator, model_validator

from app.ai import ChatModel
from app.core import constants as c
from app.core.config import get_settings
from app.core.prompts import PROMPTS
from app.crud.attack import AttackRepository, get_attack_repository
from app.domain.scenario import session, write
from app.domain.scenario.attack_prompt import list_threat_choices
from app.domain.shared import ask_ai
from app.domain.shared.names import is_same_name, name_match_key, shorten_text, threat_name_key
from app.schemas import scenarios as views
from app.schemas.intel import MARKER
from app.schemas.library import ThreatLibrary
from app.schemas.scenario_internal import (
    BriefSystem,
    FrozenContext,
    PlannedThreat,
    ScenarioDraft,
    WriterBrief,
    WrittenScenario,
)

_EVERY_MATRIX: Final = frozenset(c.ATTACK_MATRIX_NAMES)
#: A name written as text: an ATT&CK ID first ("T0836: Modify Parameter", "G0034 Sandworm Team"), then the name.
_WRITTEN_ID: Final = re.compile(r"(?is)\s*([A-Z]{1,2}\d{4}(?:\.\d{3})?)\b[\s:,\-\u2013\u2014]*(.*)")


def _clean_prose(text: str) -> str:
    """The AI's words as a story may show them: no marker (code's own), public number or link."""
    return write.remove_ids_and_links(MARKER.sub("", text))


class AttackName(BaseModel):
    """A group, technique or mitigation as the AI names it."""

    id: str | None = None
    name: str | None = None
    why: str | None = None  # a group only: why it would act

    @model_validator(mode="before")
    @classmethod
    def read_written_out(cls, value: Any) -> Any:
        """A name the AI wrote as text instead of {id, name} reads as its ID and name."""
        if not isinstance(value, str):
            return value
        found = _WRITTEN_ID.fullmatch(value)
        return {"id": found[1], "name": found[2].strip()} if found else {"name": value.strip()}

    @field_validator("why")
    @classmethod
    def clean_the_reason(cls, value: str | None) -> str | None:
        """The reason cleaned as a story's prose is."""
        return _clean_prose(value) if value else value


class AttackScenarioAnswer(BaseModel):
    """One slot of the attack writer's answer; code confirms what it names."""

    scenario_title: str
    scenario_statement: str
    risk_statement: str
    assumptions: list[str] = []
    threat_category: str
    threat_type: str
    threat: str
    threat_group: AttackName
    techniques: list[AttackName]
    mitigations: list[AttackName] = []
    entry_point: str | None = ""

    @field_validator("scenario_title", "scenario_statement", "risk_statement", "threat")
    @classmethod
    def clean_the_text(cls, value: str) -> str:
        """The title, statement, risk and threat cleaned as a story's prose is; none is left blank."""
        cleaned = _clean_prose(value)
        if not cleaned:
            raise ValueError(c.AnswerProblem.TEXT_REQUIRED)
        return cleaned

    @field_validator("assumptions")
    @classmethod
    def clean_the_assumptions(cls, value: list[str]) -> list[str]:
        """Each assumption cleaned as a story's prose is; a blank one is left out."""
        return [cleaned for text in value if (cleaned := _clean_prose(text))]


@dataclasses.dataclass(frozen=True)
class CheckedScenario:
    """One slot's answer after the checks: what the library and MITRE ATT&CK in MongoDB confirm of it."""

    answer: AttackScenarioAnswer | None = None  # None: no item for the slot, or one that breaks the contract
    category: c.StrideCategory | None = None
    threat_type: tuple[int, str] | None = None  # the library type it copied: id and name
    group: dict[str, Any] | None = None  # the tsg_attack object
    techniques: tuple[dict[str, Any], ...] = ()  # objects, each with "use" (the group's link or None), "mitigated_by"
    mitigations: tuple[dict[str, Any], ...] = ()  # the named ones MongoDB holds
    problems: tuple[str, ...] = ()  # what the checks fault: told in the re-ask when the slot is lost, else logged
    refusal: str = ""  # why no scenario is shown; "": confirmed
    is_left_out: bool = False  # the reply held no item for the slot


#: A set's slots after the checks, by slot label.
CheckedSet = dict[str, CheckedScenario]
#: An answer as read ({scenarios, other_risks}), its other risks as confirmed and what the checks found of its slots.
_ReadSet = tuple[dict[str, Any], list[dict[str, str]], CheckedSet]


def build_starting_plan(context: FrozenContext, now: datetime) -> dict[str, Any]:
    """An attack run's plan before any AI call: the first set's empty slots, its set, batch, trace and counts."""
    settings = get_settings()
    target, first = settings.total_scenario_count, settings.initial_set_size
    systems = [system["id"] for system in context.systems]
    paths = [_build_slot_path(rank, systems) for rank in range(1, (min(first, target) if target else first) + 1)]
    asked, batch = session.pick_next_paths_to_write(paths, len(paths))
    counts = dict.fromkeys(views.PlanCounts.model_fields, 0) | count_attack_plan(paths) | {"first_set": len(asked)}
    plan = {
        "prompt_version": c.PromptVersion.ATTACK_WRITER,
        "threats": [_build_empty_threat(path) for path in paths],
        "paths": paths,
        "target": target,
        "frozen_at": now,
        "risks_listed_at": None,  # set by the run's first call, which lists the other risks
        "risks_complete": False,  # set once a call asked for other risks lists none: no later call asks
    }
    trace = {"counts": counts, "landscape_cut": False, "drops": [], "drops_total": 0}
    return {"plan": plan, "plan_trace": trace, "set": asked, "batch": batch, "counts": session.count_plan_paths(paths)}


def _build_slot_path(rank: int, systems: list[int], risk: dict[str, str] | None = None) -> dict[str, Any]:
    path_id = f"a{rank:03d}"
    return {
        "path_id": path_id,
        "rank": rank,
        "served": None,
        "attempts": 0,
        "abandoned": False,
        "selected": True,
        "unselected_reason": None,
        "steps": [f"ai:{path_id}"],
        "category": "",  # the AI's, once its scenario is written
        "category_id": None,
        "categories": [],
        "systems": list(systems),
        "entry_points": [],
        "entry_system": None,
        "impact": 0,
        "confidence": 0.0,
        "also_applies": [],
        "risk": risk,  # {title, risk} the first call listed; None: the AI takes its most relevant risk
    }


def _build_empty_threat(path: dict[str, Any]) -> dict[str, Any]:
    return {
        "key": path["steps"][0],
        "library_id": None,
        "ai_generated": True,
        "type": {"id": None, "name": ""},
        "name": "",
        "category": None,
        "categories": [],
        "systems": list(path["systems"]),
        "actors": [],
    }


def count_attack_plan(paths: Iterable[dict[str, Any]]) -> dict[str, int]:
    """The plan trace's counts an attack plan changes: one AI threat a path, selected or a spare."""
    paths = [path for path in paths if not is_without_risk(path)]
    selected = sum(bool(path["selected"]) for path in paths)
    total = len(paths)
    return {
        "threats": total,
        "ai_threats": total,
        "paths": total,
        "selected": selected,
        "not_selected": total - selected,
    }


def is_without_risk(path: dict[str, Any]) -> bool:
    """Whether the path is a first-set slot the AI found no further risk for: never asked, never counted."""
    return bool(path.get("unselected_reason") == c.UnselectedReason.NO_FURTHER_RISK)


def is_listing_risks(plan: dict[str, Any], regenerate: bool) -> bool:
    """Whether a write call asks for other risks: the run's first, then a set's while the plan may still grow."""
    if plan.get("risks_listed_at") is None:
        return True
    target, selected = plan.get("target") or 0, sum(bool(path["selected"]) for path in plan["paths"])
    return not (regenerate or plan.get("risks_complete")) and (not target or selected < target)


def read_attack_answer(answer: dict[str, Any], asked: set[str]) -> tuple[dict[str, Any] | None, list[str]]:
    """The answer's items by asked slot and its other risks with the names each gives; or why it answers no slot."""
    kept, problems = ask_ai.answers_for_asked_slots(answer, "scenarios", asked)
    if not kept:  # never without a problem: not a list, or each asked slot has no answer
        return None, problems
    unescaped = (json.loads(json.dumps(item, ensure_ascii=False).replace("&amp;", "&")) for item in kept)
    scenarios = {str(item["slot"]): item for item in unescaped}
    taken = {name_match_key(str(item.get("scenario_title") or "")) for item in scenarios.values()}
    risks = []
    listed = answer.get("other_risks")
    for risk in listed if isinstance(listed, list) else []:  # ponytail: no cap, the answer's token room bounds it
        fields = risk if isinstance(risk, dict) else {}
        title, text = (_clean_prose(str(fields.get(name) or "")) for name in ("title", "risk"))
        if title and name_match_key(title) not in taken:
            taken.add(name_match_key(title))
            names = [_read_name(fields.get(part)) for part in ("threat_group", "technique")]
            risks.append({"title": title, "risk": text, "names": names})
    return {"scenarios": scenarios, "other_risks": risks}, []


def _read_name(value: Any) -> AttackName:
    if isinstance(value, str):
        return AttackName.model_validate(value)
    fields = value if isinstance(value, dict) else {}
    return AttackName(id=str(fields.get("id") or ""), name=str(fields.get("name") or ""))


def confirm_attack_set(
    scenarios: dict[str, Any],
    asked: Collection[str],
    sides: Collection[str],
    library: ThreatLibrary,
    attack: AttackRepository,
    given: str = "",
    other_risks: Sequence[dict[str, Any]] = (),
) -> tuple[list[dict[str, str]], CheckedSet]:
    """The listed risks MITRE ATT&CK confirms, and each asked slot's item as its contract and it do, in three reads."""
    choices = list_threat_choices(library)
    read = {label: _read_slot_answer(scenarios.get(label), choices, given) for label in sorted(asked)}
    told = [slot.answer for slot in read.values() if slot.answer]
    named = [name for answer in told for name in (answer.threat_group, *answer.techniques, *answer.mitigations)]
    named += [name for risk in other_risks for name in risk["names"]]
    ids = {_read_attack_id(name) for name in named} - {""}
    objects = attack.find_objects(ids, {name_match_key(name.name or "") for name in named} - {""})
    found = {label: _confirm_names(slot, sides, objects) if slot.answer else slot for label, slot in read.items()}
    groups = {slot.group["stix_id"] for slot in found.values() if slot.group}
    techniques = {technique["stix_id"] for slot in found.values() for technique in slot.techniques}
    uses = {(use["source_ref"], use["target_ref"]): use for use in attack.find_uses(groups, techniques)}
    mitigated: dict[str, list[dict[str, Any]]] = {}
    for row in attack.find_mitigations(techniques):
        mitigated.setdefault(row["technique_ref"], []).append(row)
    return _keep_confirmed_risks(other_risks, sides, objects), {
        label: dataclasses.replace(
            slot,
            techniques=tuple(
                technique
                | {
                    "use": uses.get(((slot.group or {}).get("stix_id"), technique["stix_id"])),
                    "mitigated_by": mitigated.get(technique["stix_id"], []),
                }
                for technique in slot.techniques
            ),
        )
        for label, slot in found.items()
    }


def ask_for_confirmed_set(
    chat: ChatModel,
    prompt: ask_ai.ChatPrompt,
    asked: set[str],
    sides: Collection[str],
    library: ThreatLibrary,
    is_first_call: bool,
    given: str,
) -> tuple[list[dict[str, str]], CheckedSet]:
    """One write call's other risks and asked slots as confirmed; a slot that would be lost is re-asked once."""
    first: list[_ReadSet] = []  # the first answer, once it is usable and checked

    def confirm(read: dict[str, Any]) -> _ReadSet:
        store, risks = get_attack_repository(), read["other_risks"]
        return read, *confirm_attack_set(read["scenarios"], asked, sides, library, store, given, risks)

    def find_problems(answer: dict[str, Any]) -> list[str]:
        read, _ = read_attack_answer(answer, asked)
        assert read is not None  # only a usable answer is checked
        first.append(confirm(read))
        lines = [
            f"slot {label}: {problem}"
            for label, slot in first[0][2].items()
            if slot.refusal and not (is_first_call and slot.is_left_out)  # lost; a first call may leave one out
            for problem in slot.problems
        ]
        return [PROMPTS["scenario"]["attack"]["reask"], *lines] if lines else []

    read = ask_ai.ask_ai_and_check(
        chat,
        c.AiTask.WRITE_SCENARIO,
        prompt,
        partial(read_attack_answer, asked=asked),
        first_answer_check=find_problems,
        reuse_earlier_answer=True,
    )
    if first and first[0][0] == read:  # the first answer was kept
        return first[0][1:]
    again = confirm(read)
    return _merge_reasked_set(first[0], again) if first else again[1:]


def _merge_reasked_set(first: _ReadSet, again: _ReadSet) -> tuple[list[dict[str, str]], CheckedSet]:
    """A re-asked set's other risks and slots: only a slot the first answer would lose takes the re-ask's."""
    (_, first_risks, first_found), (_, again_risks, again_found) = first, again
    merged = {}
    for label, old in first_found.items():
        new = again_found[label]
        is_no_better = bool(new.refusal) and new.answer is None
        merged[label] = old if not old.refusal or is_no_better else new
    titles = {name_match_key(slot.answer.scenario_title) for slot in merged.values() if slot.answer}
    listed = first_risks or again_risks  # the list of the answer most slots keep
    return [risk for risk in listed if name_match_key(risk["title"]) not in titles], merged


def _keep_confirmed_risks(
    other_risks: Sequence[dict[str, Any]], sides: Collection[str], objects: Sequence[dict[str, Any]]
) -> list[dict[str, str]]:
    """The listed risks ({title, risk}) whose group and technique MITRE ATT&CK holds: another is never planned."""
    kinds = ((c.AttackObjectType.GROUP, False), (c.AttackObjectType.TECHNIQUE, True))
    return [
        {"title": risk["title"], "risk": risk["risk"]}
        for risk in other_risks
        if not any(
            isinstance(_find_named_object(name, kind, sides, objects, on_a_side), str)
            for name, (kind, on_a_side) in zip(risk["names"], kinds, strict=True)
        )
    ]


def _read_attack_id(name: AttackName) -> str:
    return (name.id or "").strip().upper()


def _read_slot_answer(
    item: Any, choices: tuple[list[c.StrideCategory], list[tuple[int, str]]], given: str
) -> CheckedScenario:
    problems: list[str] = [c.AttackMessage.SLOT_MISSING]
    if item is not None:
        problems = write.find_not_english_problems(item, given)
        problems = problems or ask_ai.answer_item_problems(AttackScenarioAnswer, item, "the reply")
    if not problems:
        fields = {key: value for key, value in item.items() if key in AttackScenarioAnswer.model_fields}
        answer = AttackScenarioAnswer.model_validate(fields)
        categories, types = choices
        named = name_match_key(answer.threat_category)
        category = next((kind for kind in categories if name_match_key(kind) == named), None)
        key = threat_name_key(answer.threat_type)
        threat_type = next((pair for pair in types if key and threat_name_key(pair[1]) == key), None)
        problems = [c.AttackMessage.CATEGORY_NOT_LISTED] * (category is None)
        problems += [c.AttackMessage.TYPE_NOT_LISTED] * (threat_type is None)
        if not problems:
            return CheckedScenario(answer, category, threat_type)
    message = c.ErrorMessage.AI_ANSWER_REJECTED.format(task=c.AiTask.WRITE_SCENARIO, problems="; ".join(problems[:3]))
    refusal = shorten_text(message, c.Writing.PROBLEM_MAX_CHARS)
    return CheckedScenario(problems=tuple(problems), refusal=refusal, is_left_out=item is None)


def _confirm_names(slot: CheckedScenario, sides: Collection[str], objects: Sequence[dict[str, Any]]) -> CheckedScenario:
    assert slot.answer is not None
    problems: list[str] = []

    def find_each(named: Sequence[AttackName], kind: c.AttackObjectType, on_a_side: bool) -> list[dict[str, Any]]:
        """The distinct objects `named` mean; each one not found adds its problem."""
        kept: dict[str, dict[str, Any]] = {}
        for name in named:
            if not (_read_attack_id(name) or (name.name or "").strip()):
                continue
            found = _find_named_object(name, kind, sides, objects, on_a_side)
            if isinstance(found, str):
                problems.append(found)
            else:
                kept[found["stix_id"]] = found
        return list(kept.values())

    groups = find_each([slot.answer.threat_group], c.AttackObjectType.GROUP, False)
    techniques = find_each(slot.answer.techniques, c.AttackObjectType.TECHNIQUE, True)
    mitigations = find_each(slot.answer.mitigations, c.AttackObjectType.MITIGATION, False)
    if not groups:
        problems.append(c.AttackMessage.NO_GROUP)
    if not techniques:
        problems.append(c.AttackMessage.NO_TECHNIQUE.format(matrix=_name_matrices(sides)))
    told = "; ".join(problem.rstrip(".") for problem in problems)
    refusal = c.AttackMessage.SCENARIO_NOT_CONFIRMED.format(problems=told) if not (groups and techniques) else ""
    return dataclasses.replace(
        slot,
        group=groups[0] if groups else None,
        techniques=tuple(techniques),
        mitigations=tuple(found for found in mitigations if found["attack_id"] not in c.ControlLinks.NOT_MITIGATIONS),
        problems=tuple(problems),
        refusal=shorten_text(refusal, c.Writing.PROBLEM_MAX_CHARS),
    )


def _name_matrices(sides: Collection[str]) -> str:
    return " or ".join(c.ATTACK_MATRIX_NAMES[side] for side in sorted(sides))


def _find_named_object(
    name: AttackName,
    kind: c.AttackObjectType,
    sides: Collection[str],
    objects: Sequence[dict[str, Any]],
    on_a_side: bool,
) -> dict[str, Any] | str:
    """The one object `name` means: its ATT&CK ID's when the name is that entry's own, else its exact name's."""
    attack_id, key, given = _read_attack_id(name), name_match_key(name.name or ""), (name.name or "").strip()
    label = attack_id or given

    def keep_fitting(found: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The distinct objects of the kind among `found` (`on_a_side`: of `sides` only)."""
        of_kind = [held for held in found if held["type"] == kind]
        fitting = [held for held in of_kind if held["source"] in sides]
        return list({held["stix_id"]: held for held in (fitting if fitting or on_a_side else of_kind)}.values())

    by_id = [held for held in objects if attack_id and held["attack_id"] == attack_id]
    by_name = [held for held in objects if key and key in held["name_keys"]]
    numbered, named = keep_fitting(by_id), keep_fitting(by_name)
    # ponytail: a name is the ID's own when one holds the other's whole words ("Sandworm" for "Sandworm Team") or
    # they differ only by spaces ("Multifactor"), and it is no entry's exact name ("Remote Services" for T0866)
    is_own = len(numbered) == 1 and any(
        f" {key} " in f" {known} " or f" {known} " in f" {key} " or key.replace(" ", "") == known.replace(" ", "")
        for known in numbered[0]["name_keys"]
    )
    if by_id and (not key or any(held in by_name for held in by_id) or not named and is_own):
        named = numbered  # the ID and the name are one entry's: its matrix decides
    elif len(numbered) == 1 and len(named) != 1:  # the name is no one entry's: neither is trusted
        return c.AttackMessage.NAME_MISMATCH.format(attack_id=attack_id, found=numbered[0]["name"], given=given)
    if len(named) == 1:  # by its exact name when the ID is another entry's: the AI recalls a name better than a number
        return named[0]
    if named:  # the ID's own entries, or a name several entries have
        return c.AttackMessage.NAME_NOT_UNIQUE.format(name=label if named is numbered else given)
    found = by_id or by_name
    if found and not any(held["type"] == kind for held in found):
        other = c.AttackObjectType(found[0]["type"]).name.lower()
        return c.AttackMessage.WRONG_KIND.format(name=label, found=other, wanted=kind.name.lower())
    return c.AttackMessage.NOT_FOUND.format(name=label, matrix=_name_matrices(sides if on_a_side else _EVERY_MATRIX))


def extend_attack_plan(
    paths: Sequence[dict[str, Any]],
    answered: Collection[str],
    other_risks: Iterable[dict[str, str]],
    titles_used: Iterable[str],
    target: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The count rule: the new listed risks fill the open slots not answered yet, then add paths."""
    held = (*titles_used, *(path["risk"]["title"] for path in paths if path.get("risk")))
    taken = {name_match_key(title) for title in held}  # written or planned already: never planned twice
    risks = (risk for risk in other_risks if name_match_key(risk["title"]) not in taken)
    for path in paths:
        if path["path_id"] not in answered and not path.get("risk") and session.is_still_to_write(path):
            path["risk"] = next(risks, None)
            if path["risk"] is None:  # never padded: no further risk was found for the slot
                path |= {"selected": False, "unselected_reason": c.UnselectedReason.NO_FURTHER_RISK}
    room = target - sum(bool(path["selected"]) for path in paths)
    added = []
    for place, risk in enumerate(risks):
        path = _build_slot_path(len(paths) + place + 1, paths[0]["systems"], risk)
        if target and place >= room:
            path |= {"selected": False, "unselected_reason": c.UnselectedReason.TARGET_REACHED}
        added.append(path)
    return added, [_build_empty_threat(path) for path in added]


def build_slot_threat(
    threat: dict[str, Any], path: dict[str, Any], found: CheckedScenario, library: ThreatLibrary
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A confirmed slot's plan threat (the group acting) and its path's category and risk; a new version keeps them."""
    assert found.answer is not None and found.group is not None
    assert found.category is not None and found.threat_type is not None
    why = " ".join((found.answer.threat_group.why or "").split())
    acting = {"id": None, "name": found.group["name"], "role": c.ActorRole.ACTING, "closest": False}
    attacker = {
        "actors": [acting],
        "attacker_check": c.AttackerCheck.CHOSEN,
        "attacker_check_reason": f"{found.group['attack_id']}: {why}" if why else found.group["attack_id"],
    }
    if path["served"] and threat.get("name"):
        return threat | attacker, {}
    category, (type_id, type_name) = found.category, found.threat_type
    planned = PlannedThreat(
        threat["key"],
        None,
        type_id,
        type_name,
        " ".join(found.answer.threat.split()),
        (category,),
        reasons={category: why},
        systems=tuple(path["systems"]),
    )
    category_ids = {name.strip().lower(): row_id for row_id, name in library.category_ids}
    record = planned.to_record(category_ids) | attacker | {"confidence": None}  # no gate judged it
    title, risk = (" ".join(text.split()) for text in (found.answer.scenario_title, found.answer.risk_statement))
    return record, {
        "category": category,
        "category_id": record["category_id"],
        "categories": [category],
        "risk": path.get("risk") or {"title": title, "risk": risk},  # its own: a retried job asks for it again
    }


def draft_attack_scenario(
    context: FrozenContext, path: dict[str, Any], threat: dict[str, Any], found: CheckedScenario, given: str
) -> tuple[WriterBrief, WrittenScenario]:
    """The confirmed slot as the brief and the scenario, safety-checked, the path saver saves; every system applies."""
    assert found.answer is not None
    answer, systems = found.answer, context.find_systems(path["systems"])
    names = [system["name"] for system in systems]
    draft = ScenarioDraft(
        title=answer.scenario_title,
        statement=answer.scenario_statement,
        risk=answer.risk_statement,
        assumptions=tuple(answer.assumptions),
        entry_point=next((name for name in names if is_same_name(name, answer.entry_point or "")), ""),
        system_reasons=tuple((name, c.Writing.REACHED_REASON) for name in names),
    )
    brief = WriterBrief(
        asset={},
        systems=tuple({"name": name} for name in names),
        facts={},
        threat=threat["name"],
        threat_actions=(),
        supporting_systems=tuple(BriefSystem(system["id"], system["name"], True) for system in systems),
        entry_options=tuple(names),
        brief_text=given,
    )
    # the AI's threat name and the group's reason are checked with the draft: they are shown with it
    told = dataclasses.replace(draft, assumptions=(*draft.assumptions, threat["name"], threat["attacker_check_reason"]))
    return brief, WrittenScenario(draft, write.apply_safety_checks(brief, told).findings)


def build_attack_card(
    run: dict[str, Any],
    path: dict[str, Any],
    threat: dict[str, Any],
    brief: WriterBrief,
    written: WrittenScenario,
    found: CheckedScenario,
    replaces: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The card build_scenario_card makes, with what MITRE ATT&CK confirmed and a cited sentence per technique."""
    assert found.group is not None
    record = write.build_scenario_card(run, path, threat, brief, written, replaces)
    by_recorded_use = sorted(found.techniques, key=lambda technique: technique["use"] is None)
    cited = by_recorded_use[: c.AttackCard.CITED_TECHNIQUES]
    searched_at = record["created_at"].isoformat()
    evidence = [
        _build_evidence_entry(number, technique, found, searched_at) for number, technique in enumerate(cited, 1)
    ]
    sentences = [f"{entry['supports']} [{entry['n']}]." for entry in evidence]
    content = record["content"]
    content["statement"] = " ".join([content["statement"], *sentences])
    is_use_recorded = any(technique["use"] for technique in cited)
    documented = c.EvidenceMode.SOURCE_DOCUMENTED if is_use_recorded else c.EvidenceMode.INFERRED
    content |= {"evidence": evidence, "evidence_mode": documented, "prompt_version": c.PromptVersion.ATTACK_WRITER}
    content["attack"] = {
        "group": {"id": found.group["attack_id"], "name": found.group["name"]},
        "techniques": [
            {
                "id": technique["attack_id"],
                "name": technique["name"],
                "source": technique["source"],
                "mitigations": [row["attack_id"] for row in technique["mitigated_by"]],  # as ATT&CK records them
            }
            for technique in found.techniques
        ],
        "mitigations": [{"id": held["attack_id"], "name": held["name"]} for held in found.mitigations],
    }
    return record


def _build_evidence_entry(
    number: int, technique: dict[str, Any], found: CheckedScenario, searched_at: str
) -> dict[str, Any]:
    assert found.group is not None
    use, named = technique["use"], {held["attack_id"] for held in found.mitigations}
    recorded = technique["mitigated_by"]
    mitigations = [row["name"] for row in recorded if row["attack_id"] in named]
    mitigations += [row["name"] for row in recorded if row["attack_id"] not in named]
    matrix = c.ATTACK_MATRIX_NAMES[technique["source"]]
    wording = c.AttackMessage.USED_BY if use else c.AttackMessage.IS_TECHNIQUE  # only a recorded use is claimed
    supports = wording.format(group=found.group["name"], technique=technique["name"], matrix=matrix)
    facts = [use["description"], *(f"{cited['name']}: {cited['url']}" for cited in use["citations"])] if use else []
    return {
        "n": number,
        "ref": technique["attack_id"],
        "kind": c.IntelKind.TECHNIQUE,
        "source": technique["source"],
        "title": technique["name"],
        "url": technique["url"],
        "facts": [fact for fact in facts if fact],
        "mitigations": list(dict.fromkeys(mitigations)),
        "supports": supports.removesuffix("."),
        "role": c.EvidenceRole.CONTEXT,
        "searched_at": searched_at,
        "fetched_at": None,  # tsg_attack keeps the source's version, not a fetch time
    }
