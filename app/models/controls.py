"""A written scenario's mapped controls (Step 13; spec v4.0 §7.5; BUILD_PLAN S32): library rows only, ranked,
each with its rerank score and whether it reached the cut-off."""

from dataclasses import dataclass
from typing import Any

from app.core.constants import ControlMatch


@dataclass(frozen=True)
class MappedControl:
    control_id: int
    code: str
    name: str
    domain: str | None
    asset_type: str | None
    rank: int  # 1..n, contiguous
    score: float  # the reranker's 0-100
    match: ControlMatch
    description: str | None = None  # kept with the mapping: the results show it without reading the library

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
        }


@dataclass(frozen=True)
class ControlMapping:
    """One scenario's controls: every one at or above the cut-off, or the single nearest with a warning."""

    items: tuple[MappedControl, ...]
    query: str  # what was searched and reranked: kept, so a reviewer can see why these controls came back
    warning: str | None = None  # set when no control reached the cut-off (the nearest was kept)
