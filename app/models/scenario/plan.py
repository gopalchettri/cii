"""The threat plan: gate verdicts, planned threats, attack paths and the planner's AI answer contracts.
Frozen, so the parallel category checks share them safely."""

from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.constants import (
    ActorRole,
    AnswerProblem,
    AttackerCheck,
    StrideCategory,
)
from app.models.library.library import LibraryThreat


@dataclass(frozen=True)
class ActorPick:
    """The gate's pick for one threat: the most plausible listed attacker, and why."""

    name: str | None  # as the library spells it; None: no listed attacker plausibly could
    reason: str  # one sentence: the access, skill and motive the threat needs


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
    entry_points: tuple[int, ...] = ()  # the systems among `systems` an attacker could get in through


@dataclass(frozen=True)
class KindPlace:
    """Where and how strongly a threat applies as one kind of attack: that category's own verdict."""

    systems: tuple[int, ...]  # the systems it involves; () = the asset itself
    impact: int
    confidence: float
    actor_pick: ActorPick | None = None  # that category's attacker pick
    entry_points: tuple[int, ...] = ()  # its ways in among `systems`; () with systems: all of them


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
    # Each accepted category's own systems, impact and confidence; a category not here reads the threat's.
    kind_places: tuple[tuple[str, KindPlace], ...] = ()
    attacker_check: AttackerCheck | None = None
    attacker_check_reason: str = ""
    actor_pick: ActorPick | None = None  # the gate's pick, until code decides


@dataclass
class CategoryAudit:
    """What threat finding did for one STRIDE category."""

    category: StrideCategory
    judged_ids: set[int] = field(default_factory=set)  # library threats whose verdict came back
    # {threat, library_id, code, detail}, and `under`: the category a need refusing it everywhere came from
    rejected: list[dict[str, Any]] = field(default_factory=list)
    not_judged: list[LibraryThreat] = field(default_factory=list)  # in a gate batch that was skipped
    gap_fill_lost: dict[str, Any] | None = None  # the AI's proposal not kept: {threat, reason, detail}


@dataclass(frozen=True)
class Landscape:
    """The asset and its supporting systems as one text for the AI, each system by alias, never by id."""

    text: str
    system_ids: dict[str, int]  # alias -> supporting system id
    system_names: dict[str, str]  # alias -> name, to turn an alias the AI still wrote back into the name
    sector: str  # the asset's sector, sub-sector and critical service in one line ('' when none is set)
    cut: bool = False  # facts were shortened to fit the prompt (every system kept its name)


@dataclass(frozen=True)
class ThreatFindings:
    threats: list[PlannedThreat]
    audits: list[CategoryAudit]
    landscape: Landscape  # the text the threats were judged against
    library_stamp: dict[str, str | None] = field(default_factory=dict)  # SHA-256 per library table, hex
    # Every live category's id by its lower-case name, so a path keeps its card's category id.
    category_ids: dict[str, int] = field(default_factory=dict)
    # Candidates that left outside the gate's audits (plan_trace drops: before the gate, merged, no attacker).
    drops: list[dict[str, Any]] = field(default_factory=list)
    library_threats: int = 0  # library threats looked at
    ai_threats: int = 0  # gap-fill threats proposed and accepted


@dataclass(frozen=True)
class AttackPath:
    """One attack path: one threat on a scope ("system:<id>", "systems:<ids>" or "asset")."""

    steps: tuple[PlannedThreat, ...]
    scope: str = ""


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
    entry_points: list[str] = Field(default_factory=list)  # among `systems`: where an attacker could get in
    reason: str
    impact: Literal["HIGH", "MEDIUM", "LOW"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    needs: list[str] = Field(default_factory=list)  # what the threat needs that nothing recorded mentions
    # The attacker pick, read leniently in code: a bad one never costs a re-ask.
    attacker: Any = None
    attacker_reason: Any = None


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
