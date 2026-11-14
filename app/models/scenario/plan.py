"""The threat plan: gate verdicts, planned threats, planning drops and the gap fill's AI answer contract.
Frozen, so the parallel gate batches share them safely."""

from dataclasses import dataclass, field
from typing import Any, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from app.core.constants import (
    ActorRole,
    AttackerCheck,
    PlanStage,
    StrideCategory,
)
from app.models.library.library import LibraryActor


@dataclass(frozen=True)
class ActorPick:
    """The gate's pick for one threat: the most plausible listed attacker, and why."""

    name: str | None  # as the library spells it; None: no listed attacker plausibly could, or none named
    reason: str  # one sentence: the access, skill and motive the threat needs


@dataclass(frozen=True)
class Verdict:
    """The relevance gate's one answer for a candidate threat, for all its own categories."""

    # Every STRIDE category it named, in the gate's order: (impact rank, reason); kept when it is refused.
    named_categories: dict[StrideCategory, tuple[int, str]]
    refusal: tuple[str, str] | None  # (CandidateRejection, detail) when it does not apply; None: it applies
    systems: tuple[int, ...]  # supporting system ids; () = the asset itself
    entry_points: tuple[int, ...]  # the systems among `systems` an attacker could get in through
    confidence: float  # 0-100; 0 when not relevant
    likelihood: int  # ThreatFinding.LIKELIHOOD_RANK; 0 when not relevant
    actor_pick: ActorPick | None  # None when not relevant
    actions: tuple[str, ...]  # the acts its name states, as the gate split them


@dataclass(frozen=True)
class AttackPlace:
    """Where the threat's one attack path goes: its main category's systems, ways in and confidence."""

    systems: tuple[int, ...] = ()  # () = the asset itself
    entry_points: tuple[int, ...] = ()  # its ways in among `systems`; () = the asset itself
    confidence: float = 0.0


@dataclass(frozen=True)
class PlannedActor:
    actor_id: int
    name: str
    role: ActorRole


@dataclass(frozen=True)
class PlannedThreat:
    """One threat that applies to the asset, one record from the gate to the plan: library or gap fill."""

    key: str  # "lib:<catalogue id>" or "ai:<normalised raw name>": one threat under two categories is one
    catalogue_id: int | None  # None: an AI threat
    type_id: int  # always a library type
    type_name: str
    name: str
    # Its own categories before the gate; then those the gate accepted, in the gate's order, and the ones
    # folded in after them; stored as the main one first, then the others in STRIDE order.
    categories: tuple[StrideCategory, ...]
    reasons: dict[StrideCategory, str] = field(default_factory=dict)  # the gate's reason per category
    main_place: AttackPlace = AttackPlace()  # where its main category's attack path goes
    systems: tuple[int, ...] = ()  # every system it involves
    impact: int = 0  # the highest of its categories: what ranks it
    confidence: float = 0.0
    likelihood: int = 0  # how likely a listed attacker would attempt it; the higher on a merge
    actor_pick: ActorPick | None = None  # the gate's pick, until code decides
    actions: tuple[str, ...] = ()  # the acts its name states, systems by name: the plan's threats[].actions
    linked_actors: tuple[LibraryActor, ...] = ()  # those the library links to it (an AI threat: to its type)
    asset_type: str | None = None  # a library threat's AssetType
    actors: tuple[PlannedActor, ...] = ()  # the acting actor
    attacker_check: AttackerCheck | None = None
    attacker_check_reason: str = ""

    def to_record(self, category_ids: dict[str, int]) -> dict[str, Any]:
        """The threat as the plan stores it, its main category's library id from `category_ids`."""
        main = self.categories[0]
        return {
            "key": self.key,
            "library_id": self.catalogue_id,
            "ai_generated": self.catalogue_id is None,
            "type": {"id": self.type_id, "name": self.type_name},
            "name": self.name,
            "category": main,
            "categories": list(self.categories),
            "systems": list(self.systems),
            "reason": self.reasons[main],
            "reasons": {str(category): self.reasons[category] for category in self.categories},
            "impact": self.impact,
            "confidence": self.confidence,
            "likelihood": self.likelihood,
            "actors": [
                {"id": actor.actor_id, "name": actor.name, "role": actor.role, "closest": False}
                for actor in self.actors
            ],
            "attacker_check": self.attacker_check,
            "attacker_check_reason": self.attacker_check_reason or None,
            "actions": list(self.actions),
            "category_id": category_ids.get(main.lower()),
        }


class Drop(NamedTuple):
    """One candidate that left the plan, as planning found it; its trace entry is written from it."""

    threat_key: str
    threat_name: str  # as planned: a library name with its code, an AI name with system names
    kind: StrideCategory | None  # None: the whole threat
    stage: PlanStage
    reason: str  # PlanLoss, CandidateRejection or AttackerCheck
    detail: str = ""  # system names, never aliases


@dataclass(frozen=True)
class Landscape:
    """The asset and its supporting systems as one text for the AI, each system by alias, never by id."""

    text: str
    system_ids: dict[str, int]  # alias -> supporting system id
    system_names: dict[str, str]  # alias -> name, to turn an alias the AI still wrote back into the name
    is_cut: bool = False  # facts were shortened to fit the prompt (every system kept its name)


@dataclass(frozen=True)
class ThreatFindings:
    threats: list[PlannedThreat]
    landscape: Landscape  # the text the threats were judged against
    library_stamp: dict[str, str | None] = field(default_factory=dict)  # SHA-256 per library table, hex
    # Every live category's id by its lower-case name, so a path keeps its card's category id.
    category_ids: dict[str, int] = field(default_factory=dict)
    drops: list[Drop] = field(default_factory=list)  # every candidate that left the plan
    library_threats: int = 0  # library threats looked at
    gate_asked: int = 0  # library threat and own category pairs the gate was asked about
    ai_threats: int = 0  # gap-fill threats proposed and accepted, one per category


class GapFillResponse(BaseModel):
    """The gap-fill answer: whether a threat applies, and the one it proposes."""

    model_config = ConfigDict(extra="forbid")
    applies: bool
    reason: str
    threat_type: str | None = None
    threat: str | None = None
    systems: list[str] = Field(default_factory=list)
