"""A written scenario's mapped controls (Step 13; spec v4.0 §7.5; BUILD_PLAN S32): library rows only, ranked,
each with its rerank score, its tier (strong or fallback) and why it was kept (G225)."""

from dataclasses import dataclass
from typing import Any

from app.core.constants import CONTROL_TIERS, ControlMatch


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
    rationale: str = ""  # why it was kept: its score against the threshold, and its tier (G225)

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
    """How a scenario's controls are chosen (owner 2026-10-13, G225, G227): the candidates found, the 0-100
    threshold for strong, at least `least` (never zero: the nearest as fallback) and at most `most`."""

    cutoff: float  # CONTROL_SIMILARITY_THRESHOLD: strong at or above it
    candidates: int  # CONTROL_CANDIDATES: library controls found and scored for one scenario
    least: int  # MIN_CONTROLS (at least 1)
    most: int  # MAX_CONTROLS


@dataclass(frozen=True)
class ControlMapping:
    """One scenario's controls: the strong ones (at or above the threshold, at most MAX_CONTROLS), then, when
    fewer than MIN_CONTROLS, the nearest as fallback (never zero, G227), and what was left out (G225)."""

    items: tuple[MappedControl, ...]
    query: str  # what was searched and reranked: kept, so a reviewer can see why these controls came back
    warning: str | None = None  # set when no control reached the cut-off (the nearest were kept)
    shortfall: str | None = None  # fewer than MIN_CONTROLS kept: fewer compatible controls exist
    left_out: int = 0  # strong controls MAX_CONTROLS did not keep
    query_shortened: tuple[str, ...] = ()  # the query's parts cut to fit QUERY_MAX_CHARS (labels only, G227)
    mitigations: tuple[str, ...] = ()  # G234: the evidence's mitigations that guided the search
    ai_controls: bool = True  # G243: False when the card's threat is not about AI (no AI-domain control)


@dataclass(frozen=True)
class ControlQuery:
    """One scenario's control query (engine/scenarios/control_query.py) and which parts were shortened."""

    text: str
    shortened: tuple[str, ...] = ()  # labels such as "scenario", "risk", "system 1450": never their text
    mitigations: tuple[str, ...] = ()  # G234: the cited evidence's mitigations the query carries
