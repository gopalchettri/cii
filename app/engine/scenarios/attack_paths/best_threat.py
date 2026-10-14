"""The best-threat pick:
threat each scenario is built on, chosen by meaning instead of by numbers (impact is HIGH for most threats, so
impact and confidence rarely tell them apart). Each group of path_grouping.py (one kind of attack on the
asset through one route of systems) with two or more threats gets one AI call naming its
ThreatFinding.BEST_PICKS best threats, best first; the groups are asked at once. An answer that cannot be
read leaves its group in strength order, noted on the plan; an outage is raised, so the job retries, as for
every planner check."""

import functools
from typing import Any

import structlog

from app.ai import ChatModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.constants import STRIDE_DEFINITIONS, AiTask, LogEvent, PlanMessage, ThreatFinding
from app.core.tracing import traced
from app.engine.scenarios.attack_paths.path_grouping import GroupKey, threat_groups
from app.engine.scenarios.finding.threat_prompts import best_threat_prompt
from app.engine.shared.ask_ai import answer_item_problems, ask_ai_and_check
from app.engine.shared.names import quoted_for_prompt, shorten_text, threat_name_without_code
from app.engine.shared.parallel import run_in_parallel
from app.models.planner_replies import BestThreatPick
from app.models.threats import Landscape, PlannedThreat

log = structlog.get_logger(__name__)
_STRIDE_ORDER = list(STRIDE_DEFINITIONS)
_ASSET_ITSELF = "the asset itself"


class BestThreatPicker:
    def __init__(self, chat: ChatModel) -> None:
        self._chat = chat

    @traced("paths.best_threat")
    def pick(
        self, threats: list[PlannedThreat], landscape: Landscape
    ) -> tuple[dict[GroupKey, list[str]], list[str]]:
        """({group: its best threats' keys, best first}, the plan notes). A group of one is never asked."""
        asked = [(key, members) for key, members in threat_groups(threats).items() if len(members) > 1]
        work = functools.partial(self._pick_one, landscape)
        picks = run_in_parallel(work, asked, ThreatFinding.AI_BATCHES_AT_ONCE, "best-threat")
        chosen = {key: keys for (key, _), keys in zip(asked, picks, strict=True) if keys}
        missed = len(asked) - len(chosen)
        return chosen, [PlanMessage.BEST_THREAT_NOT_PICKED.format(groups=missed)] if missed else []

    def _pick_one(self, landscape: Landscape, group: tuple[GroupKey, list[PlannedThreat]]) -> list[str]:
        """One group's best threats by key, best first; [] when its answer could not be read."""
        (place, route), members = group
        slots = {f"{ThreatFinding.CHOICE_SLOT}{number}": threat for number, threat in enumerate(members, 1)}
        items = [_candidate(slot, threat) for slot, threat in slots.items()]
        prompt = best_threat_prompt(landscape.text, _STRIDE_ORDER[place], _target(landscape, route), items)
        read = functools.partial(_read_pick, slots=set(slots))
        try:
            best: list[str] = ask_ai_and_check(self._chat, AiTask.BEST_THREAT, prompt, read)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.BEST_THREAT, error=str(exc))
            return []
        return [slots[slot].key for slot in best]


def _candidate(slot: str, threat: PlannedThreat) -> dict[str, Any]:
    """A threat as the pick is shown it: names without library codes, and why it was judged to apply."""
    return {
        "slot": slot,
        "threat_type": threat_name_without_code(threat.type_name),
        "threat": threat_name_without_code(threat.name),
        "why": shorten_text(threat.reason, ThreatFinding.PICK_REASON_CHARS),
    }


def _target(landscape: Landscape, route: tuple[int, ...]) -> str:
    """What the group's threats were judged to apply to: the asset itself, through its route's systems."""
    if not route:
        return _ASSET_ITSELF
    return f"{_ASSET_ITSELF}, through " + " and ".join(system_named(landscape, system) for system in route)


def system_named(landscape: Landscape, system_id: int) -> str:
    """A system as the landscape names it: its alias and quoted name."""
    alias = next(alias for alias, known in landscape.system_ids.items() if known == system_id)
    return f"{alias} {quoted_for_prompt(landscape.system_names[alias])}"


def _read_pick(answer: dict[str, Any], slots: set[str]) -> tuple[list[str], list[str]]:
    """The best slots, best first: known slots only, each once, at least one, and a reason."""
    best = answer.get("best")
    if (
        not isinstance(best, list)
        or not best
        or any(not isinstance(slot, str) or slot not in slots for slot in best)
        or len(set(best)) != len(best)
    ):
        return [], [f"best must list 1 to {ThreatFinding.BEST_PICKS} of the candidate slots, each once"]
    if problems := answer_item_problems(BestThreatPick, answer, "pick"):
        return [], problems
    if not str(answer.get("reason") or "").strip():
        return [], ["the pick needs its reason"]
    return best[: ThreatFinding.BEST_PICKS], []
