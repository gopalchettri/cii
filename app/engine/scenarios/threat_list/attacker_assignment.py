"""Who carries out each threat (BLUEPRINT M10 T7, v1 threat_identification/attackers.py).

AttackerAssigner finds each threat's candidates: the actors its type links, ranked against the threat, why it
applies and the asset's sector (owner, 2026-10-10: every linked actor can carry it out, so no name check);
with none linked, the vetted pool's nearest, flagged closest. With ACTOR_SIMILARITY_THRESHOLD set, those
nearest are scored 0-100 by the reranker and only those at or above it are candidates; none reaches it: the
single best, flagged below_threshold. Linked actors are never filtered: a curator chose them. Who acts among
them is decided in attacker_choice.py from the relevance gate's pick (G229): no AI call of its own."""

import dataclasses

import structlog

from app.ai import RerankModel
from app.core.config import get_settings
from app.core.constants import LogEvent, ThreatFinding
from app.core.exceptions import Unavailable
from app.core.tracing import step_detail_enabled, traced
from app.engine.scenarios.threat_list.attacker_choice import choose_actors
from app.engine.scenarios.threat_list.attacker_trace import trace_actor_choice
from app.engine.shared.parallel import run_in_parallel
from app.models.actor_choice import ActorCandidates
from app.models.library import LibraryActor, ThreatLibrary
from app.models.threats import PlannedThreat
from app.search.snapshot import LibrarySnapshot

log = structlog.get_logger(__name__)

#: A closest-match threat's candidates, best first, and whether none reached the threshold.
ClosestOptions = tuple[tuple[LibraryActor, ...], bool]


def vetted_attackers(library: ThreatLibrary) -> tuple[LibraryActor, ...]:
    """Owner, 2026-10-10 (G122): what a type that links no attacker chooses from: the attackers the library
    links to SOME type (the curator-vetted pool; on the dev library the 9 generic attacker types, never one
    of the 40 named groups), by id. Every actor only when the library links none at all."""
    vetted = {actor for threat in library.threats for actor in threat.linked_actors}
    return tuple(sorted(vetted, key=lambda actor: actor.actor_id)) or library.actors


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
        self._closest_pool = vetted_attackers(snapshot.library.threat_library)

    @traced("threats.assign_actors")
    def assign_attackers(
        self, threats: list[PlannedThreat], sector: str, gate_judged: bool = False
    ) -> list[PlannedThreat]:
        """Every threat with its actors, all ranked with one embedding call: library and AI threats alike,
        each from the actors its type links (an AI threat's type is always a library type, G108).
        `gate_judged`: planning, where the relevance gate named a pick for each library threat."""
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
        candidates = [
            self._candidates(actors, ranking, closest.get(index))
            for index, (actors, ranking) in enumerate(zip(linked, rankings, strict=True))
        ]
        ranked_threats = [dataclasses.replace(threat, actors_ranked=ranked) for threat in threats]
        assigned = choose_actors(ranked_threats, candidates, gate_judged)
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
            return (reached, False) if reached else ((ordered[0][1],), True)

        options = run_in_parallel(offered, unlinked, ThreatFinding.AI_BATCHES_AT_ONCE, "attacker-relevance")
        return dict(zip(unlinked, options, strict=True))

    def _linked_actors(self, threat: PlannedThreat) -> tuple[LibraryActor, ...]:
        if threat.catalogue_id is not None:
            return self._linked_by_threat.get(threat.catalogue_id, ())
        return self._linked_by_type.get(threat.type_id, ())

    def _candidates(
        self, linked: tuple[LibraryActor, ...], ranking: list[LibraryActor], closest: ClosestOptions | None
    ) -> ActorCandidates:
        if linked:
            # The ranking only ORDERS the linked actors (owner, 2026-10-10, G120): one it cannot score is
            # still linked, never dropped.
            return ActorCandidates((*ranking, *[actor for actor in linked if actor not in ranking]))
        if closest is not None:
            options, below = closest
            return ActorCandidates(options, closest=True, below_threshold=below)
        # ponytail: a search with no hit at all (no shared word, no positive cosine) offers the vetted pool.
        return ActorCandidates(tuple(ranking) or self._closest_pool, closest=True)
