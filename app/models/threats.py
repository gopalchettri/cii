"""The threat plan: what threat finding produces and attack-path selection reads.
Frozen, so the parallel category checks share them safely."""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from app.core.constants import (
    STRIDE_DEFINITIONS,
    ActorRole,
    AttackerCheck,
    CandidateRejection,
    FoldReason,
    GapFillOutcome,
    StrideCategory,
)
from app.models.library import LibraryActor, LibraryThreat

#: The tie-break's "no library id": after every real one.
_NO_LIBRARY_ID = 1 << 62


def in_stride_order(categories: set[StrideCategory]) -> tuple[StrideCategory, ...]:
    return tuple(category for category in STRIDE_DEFINITIONS if category in categories)


@dataclass(frozen=True)
class Verdict:
    """The relevance gate's answer for one candidate threat."""

    relevant: bool
    systems: tuple[int, ...]  # supporting system ids; () = the asset itself
    reason: str
    impact: int  # ThreatFinding.IMPACT_RANK; 0 when not relevant
    confidence: float  # 0-100
    # What the threat needs that no recorded fact mentions (G209): a component, device or technology.
    needs: tuple[str, ...] = ()

    @property
    def applies(self) -> bool:
        """Relevant, and on recorded facts alone (G209, owner 2026-10-12): the AI may assume a missing
        detail, never that something exists; code decides, not the AI's obedience."""
        return self.relevant and not self.needs


@dataclass(frozen=True)
class PlannedActor:
    actor_id: int
    name: str
    role: ActorRole
    # A closest-match attacker that did not reach ACTOR_SIMILARITY_THRESHOLD: the nearest still acts, flagged.
    below_threshold: bool = False


@dataclass(frozen=True)
class PlannedThreat:
    """One threat that applies to the asset, whole: a library record, or one AI proposal (gap-fill)."""

    key: str  # "lib:<catalogue id>" or "ai:<normalised name>": one threat found under two categories is one
    catalogue_id: int | None  # None: an AI threat
    type_id: int  # always a library type: an AI proposal of another type is never planned (G108)
    type_name: str
    name: str
    categories: tuple[StrideCategory, ...]  # the primary first, the rest in STRIDE order
    systems: tuple[int, ...]
    impact: int
    confidence: float
    reason: str
    actors: tuple[PlannedActor, ...] = ()  # the acting actor first, then the alternates
    closest_attacker: bool = False  # its type links no actor: the nearest library actor acts (flagged)
    actors_ranked: bool = (
        True  # False: ranking unavailable, library order decided (advisory actor_not_ranked)
    )
    attacker_options: tuple[
        LibraryActor, ...
    ] = ()  # a closest attacker's nearest library actors, nearest first
    attacker_check: AttackerCheck | None = None
    attacker_check_reason: str = ""

    @property
    def from_library(self) -> bool:
        return self.catalogue_id is not None

    def to_record(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "library_id": self.catalogue_id,
            "ai_generated": not self.from_library,
            "type": {"id": self.type_id, "name": self.type_name},
            "name": self.name,
            "category": self.categories[0],
            "categories": list(self.categories),
            "systems": list(self.systems),
            "reason": self.reason,
            "impact": self.impact,
            "confidence": self.confidence,
            "actors": [
                {
                    "id": actor.actor_id,
                    "name": actor.name,
                    "role": actor.role,
                    "closest": self.closest_attacker,
                    "below_threshold": actor.below_threshold,
                }
                for actor in self.actors
            ],
            "actors_ranked": self.actors_ranked,
            "attacker_check": self.attacker_check,
            "attacker_check_reason": self.attacker_check_reason or None,
        }


@dataclass(frozen=True)
class FoldedThreat:
    """A threat that adds nothing new: `kept_key` names the threat standing for it."""

    threat: PlannedThreat
    kept_key: str
    reason: FoldReason
    score: float | None = None  # the cosine, for a same-wording fold
    why: str | None = None  # the AI's reason, for a same-attack fold


@dataclass
class CategoryAudit:
    """What threat finding did for one STRIDE category, so every outcome has its reason on the plan."""

    category: StrideCategory
    shortlisted: int = 0
    judged_ids: set[int] = field(default_factory=set)  # library threats whose verdict came back
    whole_category: bool = False  # nothing shortlisted applied: every record of the category was judged
    relevant: int = 0
    gap_fill: GapFillOutcome | None = None
    rejected: list[dict[str, Any]] = field(default_factory=list)  # {threat, library_id, code, reason}
    note: str | None = None

    @property
    def not_judged(self) -> int:
        """Threats whose gate batch stayed unusable after its retries (G210): the category is not fully
        assessed, even when its other threats gave it a scenario."""
        return sum(rejected["code"] == CandidateRejection.NOT_JUDGED for rejected in self.rejected)

    def to_record(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "shortlisted": self.shortlisted,
            "judged": len(self.judged_ids),
            "whole_category": self.whole_category,
            "relevant": self.relevant,
            "gap_fill": self.gap_fill,
            "rejected": self.rejected,
            "note": self.note,
        }


@dataclass(frozen=True)
class ThreatFindings:
    threats: list[PlannedThreat]
    audits: list[CategoryAudit]
    folded: list[FoldedThreat]
    notes: list[str]  # every quality check that could not be made, and why
    landscape: "Landscape"  # the text the threats were judged against
    # The library version it was found in: SHA-256 per table, hex (the plan's made_with.library).
    library_stamp: dict[str, str | None] = field(default_factory=dict)
    # Every live category's id by its name in lower case, from the same library: each path keeps its card's
    # category id (the results' threat_category_id), so no read ever needs the library again.
    category_ids: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackPath:
    """One attack path. Today one threat = one path: the AI never joins threats
    into chains; `steps` stays a tuple so owner-approved chain rules can add steps later (spec v4.0 §7.3).
    `scope`: what the path attacks ("system:<id>", "systems:<ids>" for a scenario merged from one attack
    through several systems (G213), or "asset"; path_grouping.path_on): the same threat on other systems is
    another path, with its own id."""

    steps: tuple[PlannedThreat, ...]
    scope: str = ""

    @property
    def path_id(self) -> str:
        keys = "|".join(step.key for step in self.steps) + (f"@{self.scope}" if self.scope else "")
        return hashlib.sha256(keys.encode()).hexdigest()[:16]

    @property
    def categories(self) -> tuple[StrideCategory, ...]:
        first = self.steps[0].categories[0]
        rest = {category for step in self.steps for category in step.categories} - {first}
        return (first, *in_stride_order(rest))

    @property
    def systems(self) -> tuple[int, ...]:
        return tuple(sorted({system for step in self.steps for system in step.systems}))

    @property
    def from_library(self) -> bool:
        return all(step.from_library for step in self.steps)

    @property
    def impact(self) -> int:
        return max(step.impact for step in self.steps)

    @property
    def confidence(self) -> float:
        return min(step.confidence for step in self.steps)

    def tie_break(self) -> tuple[bool, int, str, str]:
        """The same order on every run: library before AI, the lowest library id, the path id, the text."""
        library_ids = [step.catalogue_id for step in self.steps if step.catalogue_id is not None]
        text = " -> ".join(step.name for step in self.steps)
        digest = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
        return (not self.from_library, min(library_ids, default=_NO_LIBRARY_ID), self.path_id, digest)


@dataclass(frozen=True)
class Landscape:
    """The asset and every supporting system as the AI judges threats against them: one text, each system by
    its alias (SYS1 ...) and quoted name, never a database id."""

    text: str
    facts_shortened_note: str | None  # set when systems' facts were shortened to fit the model input
    system_ids: dict[str, int]  # alias -> supporting system id
    system_names: dict[str, str]  # alias -> name, to turn an alias the AI still wrote back into the name
    sector: str  # the asset's sector, sub-sector and critical service in one line ('' when none is set)

    @property
    def aliases(self) -> dict[int, str]:
        return {system_id: alias for alias, system_id in self.system_ids.items()}


@dataclass(frozen=True)
class CategoryFindings:
    """One STRIDE category's outcome: its relevant library threats, else its one AI threat, and its record."""

    accepted: list[tuple[LibraryThreat, Verdict]]
    ai_threat: PlannedThreat | None
    audit: CategoryAudit
