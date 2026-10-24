"""A scenario's mapped controls: library rows only, ranked, each with its rerank score, tier and reason;
and a mapped control as the API shows it."""

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from app.core.constants import CONTROL_MATCH_REASONS, CONTROL_TIERS, ControlMatch


@dataclass(frozen=True)
class MappedControl:
    control_id: int
    code: str  # the control's reference in the library
    name: str
    domain: str | None
    asset_type: str | None
    rank: int  # 1..n, contiguous
    score: float  # the reranker's 0-100
    match: ControlMatch
    description: str | None = None  # kept with the mapping: the results show it without reading the library
    rationale: str = ""  # why it was kept: its score against the threshold, and its tier

    def to_record(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "code": self.code,
            "name": self.name,
            "domain": self.domain,
            "asset_type": self.asset_type,
            "description": self.description,
            "rank": self.rank,
            "score": round(self.score, 1),
            "match": self.match,
            "tier": CONTROL_TIERS[self.match],
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ControlRule:
    """How a scenario's controls are chosen: candidates found, the 0-100 strong threshold, at least `least`
    and at most `most`; when none is strong, the `nearest` closest instead (never zero)."""

    cutoff: float  # CONTROL_SIMILARITY_THRESHOLD: strong at or above it
    candidates: int  # CONTROL_CANDIDATES: library controls found and scored for one scenario
    least: int  # MIN_CONTROLS: some strong but fewer, the nearest fill up to it
    most: int  # MAX_CONTROLS
    nearest: int  # NEAREST_CONTROLS: none strong, this many of the nearest are kept


@dataclass(frozen=True)
class ControlMapping:
    """One scenario's controls: the strong ones (at most MAX_CONTROLS), then the nearest as fallback when
    fewer than MIN_CONTROLS (never zero), and what was left out."""

    items: tuple[MappedControl, ...]
    query: str  # what was searched and reranked: kept, so a reviewer can see why these controls came back
    warning: str | None = None  # set when no control reached the cut-off (the nearest were kept)
    shortfall: str | None = None  # fewer than MIN_CONTROLS kept: fewer compatible controls exist
    left_out: int = 0  # strong controls MAX_CONTROLS did not keep
    query_shortened: tuple[str, ...] = ()  # the query's parts cut to fit QUERY_MAX_CHARS (labels only)
    mitigations: tuple[str, ...] = ()  # the evidence's mitigations that guided the search
    ai_controls: bool = True  # False when the card's threat is not about AI (no AI-domain control)
    shortlist: tuple[tuple[int, float], ...] = ()  # every candidate reranked: (control_id, 0-100 score)


@dataclass(frozen=True)
class ControlQuery:
    """One scenario's control query and which parts were shortened."""

    text: str
    shortened: tuple[str, ...] = ()  # labels such as "scenario", "risk", "system 1450": never their text
    mitigations: tuple[str, ...] = ()  # the cited evidence's mitigations the query carries


class ControlView(BaseModel):
    """A mapped control as the API shows it."""

    control_id: int
    control_code: str | None
    itot: str | None  # Control_Library.AssetType: IT, OT, IT\OT
    domain: str | None
    control_name: str | None
    control_description: str | None
    map_rank: int | None
    score: float | None  # the reranker's 0-100; None for a control the scenario's author named
    mapping_relevance: float | None  # v1's second name for the score
    match_type: str  # EXACT, NEAREST or GIVEN
    match_reason: str
    tier: str  # strong, fallback or given


def control_view(item: dict[str, Any]) -> ControlView:
    """A stored control item as the API shows it."""
    match = item.get("match")
    return ControlView(
        control_id=item["control_id"],
        control_code=item.get("code"),
        itot=item.get("asset_type"),
        domain=item.get("domain"),
        control_name=item.get("name"),
        control_description=item.get("description"),
        map_rank=item.get("rank"),
        score=item.get("score"),
        mapping_relevance=item.get("score"),
        match_type=str(match).upper(),
        match_reason=item.get("rationale") or CONTROL_MATCH_REASONS.get(str(match), ""),
        tier=item.get("tier") or CONTROL_TIERS.get(str(match), ""),
    )
