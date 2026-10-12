"""Who carries out each library threat (BLUEPRINT M10 T7, v1 threat_identification/attackers.py).

* AttackerAssigner: the actors the threat's type links, ranked against the threat, why it applies and the
  asset's sector; the first acts and the next three, best fit first, are its alternates (owner, 2026-10-10:
  every linked actor can carry out the threat, so no name check). With none linked, the library's nearest
  actor acts, flagged closest_attacker, its runners-up kept as the options the attacker check may choose
  from. With ACTOR_SIMILARITY_THRESHOLD set, those nearest actors are scored 0-100 by the reranker and only
  those at or above it are offered; none reaches it: the single best still acts, flagged below_threshold.
  Linked actors are never filtered: a curator chose them.
* AttackerFitCheck: those closest matches go to the AI once, batched: keep the nearest, pick a runner-up or
  say none fits, choosing only among library actors. A check that cannot be made keeps the nearest, noted."""

import dataclasses
import functools
from collections.abc import Callable
from typing import Any

import structlog

from app.ai import ChatModel, RerankModel, TruncatedAiAnswer, UnreadableAiAnswer
from app.core.config import get_settings
from app.core.constants import (
    ActorRole,
    Actors,
    AiTask,
    AttackerCheck,
    LogEvent,
    PlanMessage,
    ThreatFinding,
)
from app.core.exceptions import Unavailable
from app.core.tracing import step_detail_enabled, traced
from app.engine.scenarios.finding.threat_prompts import attacker_fit_prompt
from app.engine.scenarios.threat_list.attacker_trace import trace_actor_choice, trace_fit_check
from app.engine.shared.ask_ai import ChatPrompt, answers_for_asked_slots, ask_ai_and_check
from app.engine.shared.names import name_match_key, replace_codes_with_names, threat_name_without_code
from app.engine.shared.parallel import run_in_parallel
from app.engine.shared.prompt_batches import batches_that_fit, max_batch_prompt_chars
from app.models.library import LibraryActor
from app.models.threats import Landscape, PlannedActor, PlannedThreat
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)

#: A closest-match threat's attackers to offer, best first, and whether none reached the threshold.
ClosestOptions = tuple[tuple[LibraryActor, ...], bool]
#: An attacker check's answer for one slot: (the chosen actor, None for "none fits"; the reason, None when the
#: check could not be made).
AttackerChoice = tuple[LibraryActor | None, str | None]


class AttackerAssigner:
    def __init__(self, snapshot: LibrarySnapshot, rerank: RerankModel) -> None:
        self._snapshot, self._rerank = snapshot, rerank
        self._actors = snapshot.library.threat_library.actors
        threats = snapshot.library.threat_library.threats
        # A library threat's linked actors are its type's; an AI threat (no record of its own) takes those of
        # the library type it matched (G108).
        self._linked_by_threat = {threat.catalogue_id: threat.linked_actors for threat in threats}
        self._linked_by_type = {threat.type_id: threat.linked_actors for threat in threats} | {
            threat_type.type_id: threat_type.linked_actors
            for threat_type in snapshot.library.threat_library.types
        }
        # Owner, 2026-10-10 (G122): a type that links no attacker gets the nearest of the attackers the
        # library links to SOME type (the curator-vetted pool; on the dev library the 9 generic attacker
        # types, never one of the 40 named groups), found by meaning, then checked by the AI. Every actor
        # only when the library links none at all.
        vetted = {actor for threat in threats for actor in threat.linked_actors}
        self._closest_pool = tuple(sorted(vetted, key=lambda actor: actor.actor_id)) or self._actors

    @traced("threats.assign_actors")
    def assign_attackers(self, threats: list[PlannedThreat], sector: str) -> list[PlannedThreat]:
        """Every threat with its actors, all ranked with one embedding call: library and AI threats alike,
        each from the actors its type links (an AI threat's type is always a library type, G108)."""
        if not threats:
            return []
        linked = [self._linked_actors(threat) for threat in threats]
        queries = [
            f"{threat.type_name}: {threat.name}. {threat.reason} {sector}".strip() for threat in threats
        ]
        closest_pool = {actor.actor_id for actor in self._closest_pool}
        allowed = [{actor.actor_id for actor in actors} or closest_pool for actors in linked]
        hits: list[list[tuple[LibraryActor, float]]] = []  # the scores, kept for the step trace only
        try:
            hits = self._snapshot.find_actors(queries, top_k=len(self._actors), allowed_ids=allowed)
            rankings, ranked = [[actor for actor, _ in found] for found in hits], True
        except Unavailable:
            if any(not actors for actors in linked):
                raise  # the nearest actor of an unlinked type cannot be had without vectors: the job retries
            log.warning(LogEvent.PLANNER_ACTORS_NOT_RANKED, threats=len(threats))
            rankings, ranked = [list(actors) for actors in linked], False
        closest = self._closest_within_threshold(queries, linked, rankings)
        assigned = [
            self._with_actors(threat, actors, ranking, ranked, closest.get(index))
            for index, (threat, actors, ranking) in enumerate(zip(threats, linked, rankings, strict=True))
        ]
        if step_detail_enabled():
            trace_actor_choice(threats, hits, assigned)
        return assigned

    def _closest_within_threshold(
        self, queries: list[str], linked: list[tuple[LibraryActor, ...]], rankings: list[list[LibraryActor]]
    ) -> dict[int, ClosestOptions]:
        """For each threat whose type links no attacker, when ACTOR_SIMILARITY_THRESHOLD is set: its nearest
        attackers scored 0-100 by the reranker, those at or above it offered best first; none reaches it: the
        single best, flagged. One reranker call per such threat; none at all at threshold 0 (no filter)."""
        threshold = get_settings().actor_similarity_threshold
        unlinked = [index for index, actors in enumerate(linked) if not actors]
        if not threshold or not unlinked:
            return {}

        def offered(index: int) -> ClosestOptions:
            candidates = rankings[index] or list(self._closest_pool)
            scores = self._rerank.score_relevance(queries[index], [actor.name for actor in candidates])
            ordered = sorted(
                zip(scores, candidates, strict=True), key=lambda pair: -pair[0]
            )  # ties: ranking order
            reached = tuple(actor for score, actor in ordered if score >= threshold)
            return (reached[: ThreatFinding.ATTACKER_OPTIONS], False) if reached else ((ordered[0][1],), True)

        options = run_in_parallel(offered, unlinked, ThreatFinding.AI_BATCHES_AT_ONCE, "attacker-relevance")
        return dict(zip(unlinked, options, strict=True))

    def _linked_actors(self, threat: PlannedThreat) -> tuple[LibraryActor, ...]:
        if threat.catalogue_id is not None:
            return self._linked_by_threat.get(threat.catalogue_id, ())
        return self._linked_by_type.get(threat.type_id, ())

    def _with_actors(
        self,
        threat: PlannedThreat,
        linked: tuple[LibraryActor, ...],
        ranking: list[LibraryActor],
        ranked: bool,
        closest: ClosestOptions | None,
    ) -> PlannedThreat:
        threat = dataclasses.replace(threat, actors_ranked=ranked)
        if not linked:
            # ponytail: a search with no hit at all (no shared word, no positive cosine) offers the vetted
            # pool's first actors; the attacker check then judges them like any closest match.
            options, below = closest or (
                tuple(ranking[: ThreatFinding.ATTACKER_OPTIONS])
                or self._closest_pool[: ThreatFinding.ATTACKER_OPTIONS],
                False,
            )
            acting = PlannedActor(
                options[0].actor_id, options[0].name, ActorRole.ACTING, below_threshold=below
            )
            return dataclasses.replace(
                threat, actors=(acting,), closest_attacker=True, attacker_options=options
            )
        # The ranking only ORDERS the linked actors (owner, 2026-10-10, G120): one it cannot score is still
        # linked, never dropped.
        order = [*ranking, *[actor for actor in linked if actor not in ranking]]
        return dataclasses.replace(threat, actors=_acting_and_alternates(order))


def _acting_and_alternates(order: list[LibraryActor]) -> tuple[PlannedActor, ...]:
    """The first acts; the next Actors.MAX - 1 are its alternates, in the same order (best fit first, or
    library order when the ranking was unavailable)."""
    acting, alternates = order[0], order[1 : Actors.MAX]
    return (
        PlannedActor(acting.actor_id, acting.name, ActorRole.ACTING),
        *[PlannedActor(actor.actor_id, actor.name, ActorRole.ALTERNATE) for actor in alternates],
    )


class AttackerFitCheck:
    def __init__(self, chat: ChatModel, landscape: Landscape) -> None:
        self._chat = chat
        self._landscape = landscape
        self._room = max_batch_prompt_chars(chat.max_prompt_chars)

    @traced("threats.attacker_check")
    def check_attackers(self, threats: list[PlannedThreat]) -> tuple[list[PlannedThreat], list[str]]:
        """The threats with every closest-match attacker checked, and a note for each batch not checked."""
        asked = {
            f"{ThreatFinding.ATTACKER_SLOT}{position}": threat
            for position, threat in enumerate(
                (t for t in threats if t.closest_attacker and t.attacker_options), start=1
            )
        }
        if not asked:
            return threats, []
        build_prompt = functools.partial(attacker_fit_prompt, self._landscape.text)
        batches = list(
            batches_that_fit(
                build_prompt,
                [self._slot(slot, t) for slot, t in asked.items()],
                self._room,
                ThreatFinding.GATE_BATCH_MAX_ITEMS,
            )
        )
        checked = run_in_parallel(
            functools.partial(self._check_batch, asked, build_prompt),
            batches,
            ThreatFinding.AI_BATCHES_AT_ONCE,
            "attacker-check",
        )
        decided = {slot: threat for choices, _ in checked for slot, threat in choices.items()}
        notes = [note for _, batch_notes in checked for note in batch_notes]
        by_key = {threat.key: threat for threat in decided.values()}
        if step_detail_enabled():
            trace_fit_check(list(decided.values()), len(batches))
        return [by_key.get(threat.key, threat) for threat in threats], notes

    def _check_batch(
        self,
        asked: dict[str, PlannedThreat],
        build_prompt: Callable[[list[dict[str, Any]]], ChatPrompt],
        batch: list[dict[str, Any]],
    ) -> tuple[dict[str, PlannedThreat], list[str]]:
        """One attacker-check call: each slot's threat as decided, and a note when the check could not be made
        (its threats keep the nearest attacker). An outage is raised: the job retries."""
        options = {item["slot"]: asked[item["slot"]].attacker_options for item in batch}
        notes: list[str] = []
        choices: dict[str, AttackerChoice]
        try:
            read_choices = functools.partial(_read_choices, options=options)
            choices = ask_ai_and_check(self._chat, AiTask.ATTACKER_FIT, build_prompt(batch), read_choices)
        except (UnreadableAiAnswer, TruncatedAiAnswer) as exc:
            log.warning(LogEvent.PLANNER_CHECK_NOT_MADE, check=AiTask.ATTACKER_FIT, error=str(exc))
            notes.append(PlanMessage.ATTACKER_FIT_NOT_CHECKED.format(threats=len(batch)))
            choices = dict.fromkeys(options, (None, None))
        return {slot: self._decided(asked[slot], pick, why) for slot, (pick, why) in choices.items()}, notes

    def _slot(self, slot: str, threat: PlannedThreat) -> dict[str, Any]:
        aliases = self._landscape.aliases
        return {
            "slot": slot,
            "category": threat.categories[0],
            "threat_type": threat_name_without_code(threat.type_name),
            "threat": threat_name_without_code(threat.name),
            "systems": [aliases[system] for system in threat.systems if system in aliases],
            "why": threat.reason,
            "attackers": [actor.name for actor in threat.attacker_options],
        }

    def _decided(self, threat: PlannedThreat, pick: LibraryActor | None, why: str | None) -> PlannedThreat:
        """`why` None: not checked. `pick` None: none fits, the nearest stays (never blank)."""
        if why is None:
            return dataclasses.replace(threat, attacker_check=AttackerCheck.NOT_CHECKED)
        reason = replace_codes_with_names(why, self._landscape.system_names)
        if pick is None:
            return dataclasses.replace(
                threat, attacker_check=AttackerCheck.NONE_FITS, attacker_check_reason=reason
            )
        if pick == threat.attacker_options[0]:
            return dataclasses.replace(
                threat, attacker_check=AttackerCheck.FITS, attacker_check_reason=reason
            )
        return dataclasses.replace(
            threat,
            actors=(PlannedActor(pick.actor_id, pick.name, ActorRole.ACTING),),
            attacker_check=AttackerCheck.CHOSEN,
            attacker_check_reason=reason,
        )


def _read_choices(
    answer: dict[str, Any], options: dict[str, tuple[LibraryActor, ...]]
) -> tuple[dict[str, AttackerChoice], list[str]]:
    """{slot: (the chosen library actor or None for "none fits", the reason)}: an actor only from that slot's
    own list (matched as the library spells it), and a reason for every choice."""
    items, problems = answers_for_asked_slots(answer, "choices", set(options))
    choices: dict[str, AttackerChoice] = {}
    for item in items:
        slot, name = item["slot"], item.get("attacker")
        why = str(item.get("reason") or "").strip()
        if not why:
            problems.append(f"{slot}: the reason is required")
            continue
        pick = (
            None
            if name is None
            else next(
                (actor for actor in options[slot] if name_match_key(actor.name) == name_match_key(str(name))),
                None,
            )
        )
        if name is not None and pick is None:
            problems.append(f"{slot}: {str(name)[:80]!r} is not one of that slot's attackers")
            continue
        choices[slot] = (pick, why)
    return choices, problems
