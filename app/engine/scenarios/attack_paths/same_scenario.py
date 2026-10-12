"""The same-scenario check (G213, owner 2026-10-12: "merge into one"). One scenario per kind of attack on each
system wrote the same story once per system when the systems serve one purpose (asset 1207: "Exposure of
operational grid data" through the telecom network, SCADA and the ICS). Each kind of attack with two or more
scenarios on systems gets one AI call, all at once: which are the same attacker action with the same harm,
differing only in the system used. Code merges each group into ONE scenario on all its systems, written
around the member whose threat was judged to apply on the most of them (then the strongest); a member on a
system that threat was never judged on (G211: its type does not fit, or the gate never placed it there) is
merged with the group's other leftovers when it can be, else stays apart. The other members' threats join
`also_applies`, never lost, and each merge is kept on the plan with the AI's reason. A scenario on the asset
itself is never asked. An answer that cannot be read merges nothing, noted on the plan; an outage is raised,
so the job retries."""

import functools
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AiTask, LogEvent, PlanMessage, ThreatFinding
from app.core.tracing import traced
from app.engine.scenarios.attack_paths.best_threat import system_named
from app.engine.scenarios.attack_paths.path_grouping import path_on
from app.engine.scenarios.finding.threat_prompts import same_scenario_prompt
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_and_check
from app.engine.shared.names import shorten_text, threat_name_without_code
from app.engine.shared.parallel import run_in_parallel
from app.models.planner_replies import SameScenarioGroup
from app.models.threats import AttackPath, Landscape, PlannedThreat

log = structlog.get_logger(__name__)

#: A scenario as the plan builds it: its path and its other threats' names (`also_applies`).
Scenario = tuple[AttackPath, list[str]]
#: One group the AI named: its members (by index among its kind of attack's scenarios) and its reason.
Group = tuple[list[int], str]


class SameScenarioCheck:
    def __init__(self, chat: ChatModel) -> None:
        self._chat = chat

    @traced("paths.same_scenario")
    def merge(
        self, scenarios: list[Scenario], threats: Sequence[PlannedThreat], landscape: Landscape
    ) -> tuple[list[Scenario], list[str], list[dict[str, Any]]]:
        """(the scenarios, those that are one attack through several systems merged; the plan's notes; one
        record per merge: the merged path, its systems, the threats it joined and the AI's reason)."""
        by_category: defaultdict[str, list[Scenario]] = defaultdict(list)
        for scenario in scenarios:
            if scenario[0].systems:  # the asset itself is a place of its own: never merged
                by_category[scenario[0].steps[0].categories[0]].append(scenario)
        asked = [members for members in by_category.values() if len(members) > 1]
        work = functools.partial(self._same_groups, landscape)
        answers = run_in_parallel(work, asked, ThreatFinding.AI_BATCHES_AT_ONCE, "same-scenario")
        by_key = {threat.key: threat for threat in threats}
        merged, records = list(scenarios), list[dict[str, Any]]()
        for members, groups in zip(asked, answers, strict=True):
            for indexes, reason in groups or ():
                merged = _merge_group(merged, [members[index] for index in indexes], reason, by_key, records)
        notes = []
        if len(merged) < len(scenarios):
            notes.append(PlanMessage.SCENARIOS_MERGED.format(before=len(scenarios), after=len(merged)))
        if missed := sum(groups is None for groups in answers):
            notes.append(PlanMessage.SAME_SCENARIO_NOT_CHECKED.format(categories=missed))
        return merged, notes, records

    def _same_groups(self, landscape: Landscape, members: list[Scenario]) -> list[Group] | None:
        """The groups of one kind of attack, by member index, with their reasons; None when its answer could
        not be read."""
        slots = [f"{ThreatFinding.SCENARIO_SLOT}{number}" for number in range(1, len(members) + 1)]
        items = [_shown(slot, path, landscape) for slot, (path, _) in zip(slots, members, strict=True)]
        prompt = same_scenario_prompt(landscape.text, members[0][0].steps[0].categories[0], items)
        read = functools.partial(_read_groups, slots=slots)
        try:
            groups: list[tuple[list[str], str]] = ask_ai_and_check(
                self._chat, AiTask.SAME_SCENARIO, prompt, read
            )
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.SAME_SCENARIO, error=str(exc))
            return None
        return [([slots.index(slot) for slot in paths], reason) for paths, reason in groups]


def _shown(slot: str, path: AttackPath, landscape: Landscape) -> dict[str, Any]:
    """A scenario as the check is shown it: its threat (no library codes), its system by alias and name, and
    why the threat was judged to apply."""
    threat = path.steps[0]
    return {
        "slot": slot,
        "threat_type": threat_name_without_code(threat.type_name),
        "threat": threat_name_without_code(threat.name),
        "system": system_named(landscape, path.systems[0]),
        "why": shorten_text(threat.reason, ThreatFinding.PICK_REASON_CHARS),
    }


def _merge_group(
    scenarios: list[Scenario],
    group: list[Scenario],
    reason: str,
    by_key: dict[str, PlannedThreat],
    records: list[dict[str, Any]],
) -> list[Scenario]:
    """`scenarios` with `group` merged: around its best member first, then its leftovers among themselves,
    until fewer than two can join (G213 review: a group of two pairs merged only one). Each merge recorded."""
    while len(group) >= 2:
        merged = _merged(scenarios, group, by_key)
        if merged is None:
            break
        scenarios, joined, one = merged
        records.append(
            {
                "path_id": one[0].path_id,
                "systems": list(one[0].systems),
                "threats": [_name(member) for member in joined],
                "reason": reason,
            }
        )
        group = [member for member in group if not any(member is joiner for joiner in joined)]
    return scenarios


def _merged(
    scenarios: list[Scenario], group: list[Scenario], by_key: dict[str, PlannedThreat]
) -> tuple[list[Scenario], list[Scenario], Scenario] | None:
    """(`scenarios` with part of `group` made one scenario at the place of its first member, the members it
    joined, the merged scenario): written around the member whose threat applies on the most of the group's
    systems (then the strongest); a member on a system that threat never applied on is left out. None when
    fewer than two can join."""

    def joined_by(scenario: Scenario) -> list[Scenario]:
        step = scenario[0].steps[0]
        applies = set(by_key.get(step.key, step).systems)  # every system its threat was judged on
        return [member for member in group if set(member[0].systems) <= applies]

    kept = min(group, key=lambda s: (-len(joined_by(s)), -s[0].impact, -s[0].confidence, *s[0].tie_break()))
    joining = joined_by(kept)
    if len(joining) < 2:
        return None
    systems = tuple(system for member in joining for system in member[0].systems)
    others = [_name(member) for member in joining if member is not kept]
    also = dict.fromkeys([*kept[1], *others, *(name for member in joining for name in member[1])])
    one = (path_on(kept[0].steps[0], systems), [name for name in also if name != _name(kept)])
    at = next(index for index, scenario in enumerate(scenarios) if any(scenario is m for m in joining))
    rest = [scenario for scenario in scenarios if not any(scenario is member for member in joining)]
    return [*rest[:at], one, *rest[at:]], joining, one


def _name(scenario: Scenario) -> str:
    return threat_name_without_code(scenario[0].steps[0].name)


def _read_groups(answer: dict[str, Any], slots: list[str]) -> tuple[list[tuple[list[str], str]], list[str]]:
    """The groups by slot, each with its reason: known slots only, each in at most one group, two or more per
    group. Any JSON may come back: a bad shape is a problem to re-ask, never a crash."""
    same = answer.get("same")
    if not isinstance(same, list):
        return [], ['"same" must be a list of groups ([] when every scenario is different)']
    groups: list[tuple[list[str], str]] = []
    for number, group in enumerate(same, start=1):
        label = f"group {number}"
        if not isinstance(group, dict):
            return [], [f"{label} must be an object"]
        if problems := answer_item_problems(SameScenarioGroup, group, label):
            return [], problems
        paths, reason = group["paths"], str(group["reason"]).strip()
        used = {slot for earlier, _ in groups for slot in earlier}
        if (
            len(set(paths)) < 2
            or len(set(paths)) < len(paths)
            or any(s not in slots or s in used for s in paths)
        ):
            return [], [f"{label}: two or more known scenarios, each in one group only"]
        if not reason:
            return [], [f"{label} needs its reason"]
        groups.append((paths, reason))
    return groups, []
