"""The same-attack check (paths.fold_same): ONE batched AI judgment of which threats,
library ones included, are the same attack on the same systems in other words; each such group folds into the
one that stands for it. Only threats sharing a system are asked about. A check that cannot be made folds
nothing and is noted: a quality step, never the run's failure."""

import dataclasses
import functools
import itertools
from collections.abc import Callable
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import AiTask, FoldReason, LogEvent, PlanMessage, ThreatFinding, Tracing
from app.core.redaction import clipped_text
from app.core.tracing import record_detail, step_detail_enabled, traced
from app.engine.scenarios.finding.threat_prompts import same_attack_prompt
from app.engine.scenarios.threat_list.duplicate_merge import merge_two_threats
from app.engine.scenarios.threat_list.threat_codes import (
    code_to_name_map,
    systems_of_threat,
    threat_as_ai_sees_it,
    threats_by_code,
)
from app.engine.shared.ask_ai import ChatPrompt, ask_ai_and_check
from app.engine.shared.names import replace_codes_with_names
from app.engine.shared.parallel import run_in_parallel
from app.engine.shared.prompt_batches import batches_that_fit, max_batch_prompt_chars
from app.models.threats import AttackPath, FoldedThreat, Landscape, PlannedThreat

log = structlog.get_logger(__name__)

#: A same-attack group: (its threat slots, the AI's reason).
SameAttackGroup = tuple[list[str], str]


def pick_surviving_threat(members: list[PlannedThreat]) -> PlannedThreat:
    """Which twin stands for all: library before AI, then path selection's tie order (the lowest library id).
    Never its attacker: attackers are chosen after the fold."""
    return min(members, key=lambda threat: (not threat.from_library, AttackPath((threat,)).tie_break()))


class SameAttackCheck:
    def __init__(self, chat: ChatModel, landscape: Landscape) -> None:
        self._chat = chat
        self._landscape = landscape
        self._room = max_batch_prompt_chars(chat.max_prompt_chars)

    @traced("threats.same_attack")
    def merge_same_attacks(
        self, threats: list[PlannedThreat], folded: list[FoldedThreat]
    ) -> tuple[list[PlannedThreat], list[FoldedThreat], list[str]]:
        """The threats with each same-attack group folded (every category and system kept, so coverage holds);
        `folded` with each fold added and earlier folds re-pointed; a note per check not made."""
        near = [
            t
            for t in threats
            if any(other is not t and systems_of_threat(other) & systems_of_threat(t) for other in threats)
        ]
        slots = threats_by_code(near)
        groups, notes = self._ask_groups(slots)
        names = code_to_name_map(slots, self._landscape.system_names)
        by_key = {threat.key: threat for threat in threats}
        kept_as: dict[str, str] = {}
        new_folds: list[FoldedThreat] = []
        for slot_ids, why in groups:
            members = [slots[slot] for slot in slot_ids]
            keep = pick_surviving_threat(members)
            for member in (m for m in members if m is not keep):
                by_key[keep.key] = merge_two_threats(by_key[keep.key], member)
                del by_key[member.key]
                kept_as[member.key] = keep.key
                new_folds.append(
                    FoldedThreat(
                        member, keep.key, FoldReason.SAME_ATTACK, why=replace_codes_with_names(why, names)
                    )
                )
        repointed = [dataclasses.replace(f, kept_key=kept_as.get(f.kept_key, f.kept_key)) for f in folded]
        return [by_key[t.key] for t in threats if t.key in by_key], repointed + new_folds, notes

    def _ask_groups(self, slots: dict[str, PlannedThreat]) -> tuple[list[SameAttackGroup], list[str]]:
        build_prompt = functools.partial(same_attack_prompt, self._landscape.text)
        items = [
            threat_as_ai_sees_it(slot, threat, self._landscape.aliases) for slot, threat in slots.items()
        ]
        # One threat alone has no twin: no call. The batches are sent at once (review of S13c).
        batches = [batch for batch in batches_that_fit(build_prompt, items, self._room) if len(batch) >= 2]
        asked = functools.partial(self._ask_batch, slots, build_prompt)
        answers = run_in_parallel(asked, batches, ThreatFinding.AI_BATCHES_AT_ONCE, "same-attack")
        groups = [group for batch_groups, _ in answers for group in batch_groups]
        if step_detail_enabled():
            _trace_groups(slots, len(batches), groups)
        return groups, [note for _, notes in answers for note in notes]

    def _ask_batch(
        self,
        slots: dict[str, PlannedThreat],
        build_prompt: Callable[[list[dict[str, Any]]], ChatPrompt],
        batch: list[dict[str, Any]],
    ) -> tuple[list[SameAttackGroup], list[str]]:
        """One same-attack call: its groups, or a note when it could not be made (nothing folds)."""
        asked = {item["slot"]: slots[item["slot"]] for item in batch}
        try:
            read_groups = functools.partial(_read_groups, slots=asked)
            return ask_ai_and_check(self._chat, AiTask.SAME_ATTACK, build_prompt(batch), read_groups), []
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.SAME_ATTACK, error=str(exc))
            return [], [PlanMessage.SAME_ATTACK_NOT_CHECKED.format(threats=len(batch))]


def _trace_groups(slots: dict[str, PlannedThreat], batches: int, groups: list[SameAttackGroup]) -> None:
    """Each same-attack group the AI found (its threats and why), and the threat standing for each."""
    shown: dict[str, str] = {}
    survivors = []
    for number, (slot_ids, why) in enumerate(groups, start=1):
        members = [slots[slot] for slot in slot_ids]
        reason = clipped_text(why, Tracing.DETAIL_TEXT_CHARS)
        shown[f"g{number}"] = f"{' + '.join(member.name for member in members)} (why {reason})"
        survivors.append(pick_surviving_threat(members).name)
    record_detail(
        "groups",
        given={"threats_sharing_systems": len(slots), "batches": batches},
        produced={**shown, "survivors": " | ".join(survivors) or "none"},
    )


def _read_group(group: Any, number: int, slots: dict[str, PlannedThreat], used: set[str]) -> str | None:
    """The problem with one group, None when it is valid."""
    ids = group.get("threats") if isinstance(group, dict) else None
    if not isinstance(ids, list) or len(ids) < 2:
        return f"group {number}: 2 or more threat slots"
    ids = [str(slot) for slot in ids]
    if any(slot not in slots or slot in used for slot in ids) or len(set(ids)) != len(ids):
        return f"group {number}: unknown or repeated threat slot"
    if not str(group.get("reason") or "").strip():
        return f"group {number}: every group needs its reason"
    if any(
        not systems_of_threat(slots[a]) & systems_of_threat(slots[b])
        for a, b in itertools.combinations(ids, 2)
    ):
        return f"group {number}: threats on different systems are never the same attack"
    if len({slots[slot].type_id for slot in ids}) > 1:  # G109: a canonical type is never merged away
        return f"group {number}: threats of different types are never the same attack"
    return None


def _read_groups(
    answer: dict[str, Any], slots: dict[str, PlannedThreat]
) -> tuple[list[SameAttackGroup], list[str]]:
    """The valid groups; a partly bad answer keeps its valid groups (the bad group's threats stay apart), and
    only an answer with nothing usable is asked again."""
    items = answer.get("same")
    if not isinstance(items, list):
        return [], ['the reply must be {"same": [...]}']
    groups: list[SameAttackGroup] = []
    used: set[str] = set()
    problems: list[str] = []
    for number, group in enumerate(items, start=1):
        if problem := _read_group(group, number, slots, used):
            problems.append(problem)
            continue
        ids = [str(slot) for slot in group["threats"]]
        used.update(ids)
        groups.append((ids, str(group["reason"]).strip()[: ThreatFinding.LINK_MAX_CHARS]))
    if groups and problems:
        log.warning(
            LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.SAME_ATTACK, kept=len(groups), problems=problems[:5]
        )
        return groups, []
    return groups, problems
