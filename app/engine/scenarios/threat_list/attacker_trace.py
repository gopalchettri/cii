"""The step trace's inner records of attacker assignment (DEBUG_STEP_DETAIL, called only with it on): each
threat's ranked actors, the actors it ended with, and what the AI attacker check decided."""

from app.core.constants import Tracing
from app.core.tracing import ranked, record_detail
from app.models.library import LibraryActor
from app.models.threats import PlannedThreat


def trace_actor_choice(
    threats: list[PlannedThreat], hits: list[list[tuple[LibraryActor, float]]], assigned: list[PlannedThreat]
) -> None:
    """The ranking of the first DETAIL_MAX_RECORDS threats (none when the ranking was unavailable), then each
    threat's acting actor and alternates, best first."""
    for threat, found in zip(threats, hits[: Tracing.DETAIL_MAX_RECORDS], strict=False):
        record_detail(
            "actor ranking",
            threat.name,
            given={"actors_ranked": len(found)},
            produced=ranked((f"{actor.actor_id} {actor.name}", score) for actor, score in found),
        )
    record_detail(
        "acting > alternates",
        given={"threats": len(assigned), "ranked": bool(hits)},
        produced={
            threat.name: " > ".join(actor.name for actor in threat.actors)
            for threat in assigned[: Tracing.PREVIEW_KEYS]
        },
    )


def trace_fit_check(decided: list[PlannedThreat], batches: int) -> None:
    """Each closest-match threat's attacker check: its outcome and the attacker acting after it."""
    record_detail(
        "fit check",
        given={"threats": len(decided), "batches": batches},
        produced={
            threat.name: f"{threat.attacker_check} {threat.actors[0].name if threat.actors else 'none'}"
            for threat in decided[: Tracing.PREVIEW_KEYS]
        },
    )
