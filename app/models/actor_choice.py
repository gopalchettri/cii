"""Who acts for a threat (G229, owner 2026-10-13: relevant, diverse but defensible actors, with no AI call
added): the relevance gate's pick, read from the call that judged the threat, and the candidates code
decides among (engine/scenarios/threat_list/attacker_choice.py)."""

from dataclasses import dataclass

from app.models.library import LibraryActor


@dataclass(frozen=True)
class ActorPick:
    """The gate's answer for one threat: the listed attacker it judged most plausible, why, and how suitable
    it judged each listed one."""

    name: str | None  # as the library spells it; None: no listed attacker plausibly could
    reason: str  # one sentence: the access, skill and motive the threat needs
    suitability: tuple[tuple[str, str], ...] = ()  # (listed name, HIGH | MEDIUM); one not rated is LOW

    def level_of(self, name: str) -> str:
        return dict(self.suitability).get(name, "LOW")


@dataclass(frozen=True)
class ActorCandidates:
    """A threat's attackers to choose from, best search rank first: its type's linked actors, or (its type
    links none) the vetted pool's nearest, flagged."""

    order: tuple[LibraryActor, ...]
    closest: bool = False
    below_threshold: bool = False  # none of the nearest reached ACTOR_SIMILARITY_THRESHOLD
