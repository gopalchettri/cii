"""The threat plan: gate verdicts, planned threats, attack paths and the planner's AI answer contracts.
Frozen, so the parallel category checks share them safely."""

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import (
    STRIDE_DEFINITIONS,
    ActorRole,
    AnswerProblem,
    AttackerCheck,
    CandidateRejection,
    GapFillOutcome,
    StrideCategory,
)
from app.models.external_intelligence.evidence import Evidence, EvidenceSearchRecord
from app.models.library import LibraryActor, LibraryThreat

#: The tie-break's "no library id": after every real one.
_NO_LIBRARY_ID = 1 << 62


def in_stride_order(categories: set[StrideCategory]) -> tuple[StrideCategory, ...]:
    """The categories in STRIDE order."""
    return tuple(category for category in STRIDE_DEFINITIONS if category in categories)


def attacker_unsupported(check: str | None, acting: Mapping[str, Any]) -> bool:
    """True when no check backs the acting attacker (`acting` as stored), so none is attributed; a
    curator-linked actor stays. `check`: how the attacker was decided (AttackerCheck)."""
    if check == AttackerCheck.NONE_FITS:
        return True
    return bool(acting.get("closest")) and check in (AttackerCheck.NOT_CHECKED, AttackerCheck.RANKED)


@dataclass(frozen=True)
class ActorPick:
    """The gate's pick for one threat: the most plausible listed attacker, why, and each one's suitability."""

    name: str | None  # as the library spells it; None: no listed attacker plausibly could
    reason: str  # one sentence: the access, skill and motive the threat needs
    suitability: tuple[tuple[str, str], ...] = ()  # (listed name, HIGH | MEDIUM); one not rated is LOW


@dataclass(frozen=True)
class ActorCandidates:
    """A threat's attackers, best search rank first: its type's linked actors, else the pool's nearest."""

    order: tuple[LibraryActor, ...]
    closest: bool = False


@dataclass(frozen=True)
class Verdict:
    """The relevance gate's answer for one candidate threat."""

    relevant: bool
    systems: tuple[int, ...]  # supporting system ids; () = the asset itself
    reason: str
    impact: int  # ThreatFinding.IMPACT_RANK; 0 when not relevant
    confidence: float  # 0-100
    needs: tuple[str, ...] = ()  # what the threat needs that no recorded fact mentions
    actor_pick: ActorPick | None = None

    @property
    def applies(self) -> bool:
        """Relevant on recorded facts alone: the AI may assume a detail, never that something exists."""
        return self.relevant and not self.needs


@dataclass(frozen=True)
class PlannedActor:
    actor_id: int
    name: str
    role: ActorRole


@dataclass(frozen=True)
class PlannedThreat:
    """One threat that applies to the asset: a library record, or one AI proposal (gap fill)."""

    key: str  # "lib:<catalogue id>" or "ai:<normalised name>": one threat found under two categories is one
    catalogue_id: int | None  # None: an AI threat
    type_id: int  # always a library type
    type_name: str
    name: str
    categories: tuple[StrideCategory, ...]  # the primary first, the rest in STRIDE order
    systems: tuple[int, ...]
    impact: int
    confidence: float
    reason: str
    actors: tuple[PlannedActor, ...] = ()  # the acting actor
    # The gate's reason under each category it accepted the threat for; a category not here reads `reason`.
    kind_reasons: tuple[tuple[str, str], ...] = ()
    closest_attacker: bool = False  # its type links no actor: the nearest library actor acts (flagged)
    attacker_check: AttackerCheck | None = None
    attacker_check_reason: str = ""
    actor_pick: ActorPick | None = None  # the gate's pick, until code decides
    evidence: tuple[Evidence, ...] = ()  # intelligence the story may cite; set at write time only
    intel_search: EvidenceSearchRecord | None = None  # the search that found (or missed) it

    @property
    def from_library(self) -> bool:
        """True when the threat comes from the library."""
        return self.catalogue_id is not None

    def reason_for(self, kind: str) -> str:
        """Why it applies as `kind`: the gate's reason for that category, else its own reason."""
        return dict(self.kind_reasons).get(kind, self.reason)

    def reasons_by_kind(self) -> dict[str, str]:
        """Every category's own reason."""
        return {str(category): self.reason_for(category) for category in self.categories}

    def to_record(self) -> dict[str, Any]:
        """The threat as the plan stores it; evidence keys only when it was searched."""
        record: dict[str, Any] = {
            "key": self.key,
            "library_id": self.catalogue_id,
            "ai_generated": not self.from_library,
            "type": {"id": self.type_id, "name": self.type_name},
            "name": self.name,
            "category": self.categories[0],
            "categories": list(self.categories),
            "systems": list(self.systems),
            "reason": self.reason,
            "reasons": self.reasons_by_kind(),
            "impact": self.impact,
            "confidence": self.confidence,
            "actors": [
                {
                    "id": actor.actor_id,
                    "name": actor.name,
                    "role": actor.role,
                    "closest": self.closest_attacker,
                }
                for actor in self.actors
            ],
            "attacker_check": self.attacker_check,
            "attacker_check_reason": self.attacker_check_reason or None,
        }
        if self.intel_search is not None:
            record["evidence"] = [entry.as_doc() for entry in self.evidence]
            record["intel_search"] = self.intel_search.as_doc()
        return record


@dataclass
class CategoryAudit:
    """What threat finding did for one STRIDE category."""

    category: StrideCategory
    judged_ids: set[int] = field(default_factory=set)  # library threats whose verdict came back
    gap_fill: GapFillOutcome | None = None
    rejected: list[dict[str, Any]] = field(default_factory=list)  # {threat, library_id, code}

    @property
    def not_judged(self) -> int:
        """Threats whose gate batch stayed unusable after its retries: the category is not fully assessed."""
        return sum(rejected["code"] == CandidateRejection.NOT_JUDGED for rejected in self.rejected)


@dataclass(frozen=True)
class Landscape:
    """The asset and its supporting systems as one text for the AI, each system by alias, never by id."""

    text: str
    system_ids: dict[str, int]  # alias -> supporting system id
    system_names: dict[str, str]  # alias -> name, to turn an alias the AI still wrote back into the name
    sector: str  # the asset's sector, sub-sector and critical service in one line ('' when none is set)


@dataclass(frozen=True)
class ThreatFindings:
    threats: list[PlannedThreat]
    audits: list[CategoryAudit]
    landscape: Landscape  # the text the threats were judged against
    library_stamp: dict[str, str | None] = field(default_factory=dict)  # SHA-256 per library table, hex
    # Every live category's id by its lower-case name, so a path keeps its card's category id.
    category_ids: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class AttackPath:
    """One attack path: one threat on a scope ("system:<id>", "systems:<ids>" or "asset")."""

    steps: tuple[PlannedThreat, ...]
    scope: str = ""

    @property
    def path_id(self) -> str:
        """A stable id from the path's threats and scope."""
        keys = "|".join(step.key for step in self.steps) + (f"@{self.scope}" if self.scope else "")
        return hashlib.sha256(keys.encode()).hexdigest()[:16]

    @property
    def categories(self) -> tuple[StrideCategory, ...]:
        """The first step's main category, then the others in STRIDE order."""
        first = self.steps[0].categories[0]
        rest = {category for step in self.steps for category in step.categories} - {first}
        return (first, *in_stride_order(rest))

    @property
    def systems(self) -> tuple[int, ...]:
        """Every system the path's steps touch, sorted."""
        return tuple(sorted({system for step in self.steps for system in step.systems}))

    @property
    def from_library(self) -> bool:
        """True when every step comes from the library."""
        return all(step.from_library for step in self.steps)

    @property
    def impact(self) -> int:
        """The highest impact of the path's steps."""
        return max(step.impact for step in self.steps)

    @property
    def confidence(self) -> float:
        """The lowest confidence of the path's steps."""
        return min(step.confidence for step in self.steps)

    def tie_break(self) -> tuple[bool, int, str, str]:
        """The same order on every run: library before AI, the lowest library id, the path id, the text."""
        library_ids = [step.catalogue_id for step in self.steps if step.catalogue_id is not None]
        text = " -> ".join(step.name for step in self.steps)
        digest = hashlib.sha256(" ".join(text.lower().split()).encode()).hexdigest()
        return (not self.from_library, min(library_ids, default=_NO_LIBRARY_ID), self.path_id, digest)


@dataclass(frozen=True)
class CategoryFindings:
    """One STRIDE category's outcome: its relevant library threats, else its one AI threat."""

    accepted: list[tuple[LibraryThreat, Verdict]]
    ai_threat: PlannedThreat | None
    audit: CategoryAudit


class RelevanceVerdict(BaseModel):
    """One item of the relevance gate's answer."""

    model_config = ConfigDict(extra="forbid")
    slot: str
    relevant: bool
    systems: list[str]
    reason: str
    impact: Literal["HIGH", "MEDIUM", "LOW"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    needs: list[str] = Field(default_factory=list)  # what the threat needs that nothing recorded mentions
    # The attacker pick, read leniently in code: a bad one never costs a re-ask.
    attacker: Any = None
    attacker_reason: Any = None
    suitability: Any = None


class GapFillResponse(BaseModel):
    """The gap-fill answer: whether a threat applies, and the one it proposes."""

    model_config = ConfigDict(extra="forbid")
    applies: bool
    reason: str
    threat_type: str | None = None
    threat: str | None = None
    attacker: str | None = None
    systems: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_a_proposal_is_whole(self) -> "GapFillResponse":
        """A proposal names its type, threat and attacker."""
        if self.applies and not all(
            value and value.strip() for value in (self.threat_type, self.threat, self.attacker)
        ):
            raise ValueError(AnswerProblem.GAP_FILL_INCOMPLETE)
        return self
