"""A scenario's mapped control as the API shows it: the library row, its rerank score, its tier (strong,
fallback or given) and why it was kept (G225: its own rationale; one mapped before: the general reason)."""

from typing import Any

from pydantic import BaseModel

from app.core.constants import CONTROL_MATCH_REASONS, CONTROL_TIERS


class ControlView(BaseModel):
    control_id: int
    control_code: str | None
    itot: str | None  # Control_Library.AssetType: IT, OT, IT\OT
    domain: str | None
    control_name: str | None
    control_description: str | None
    map_rank: int | None
    score: float | None  # the reranker's 0-100; None for a control the scenario's author named
    match_type: str  # EXACT, NEAREST or GIVEN
    tier: str  # strong, fallback or given (G225)
    match_reason: str


def control_view(item: dict[str, Any]) -> ControlView:
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
        match_type=str(match).upper(),
        tier=item.get("tier") or CONTROL_TIERS.get(str(match), ""),
        match_reason=item.get("rationale") or CONTROL_MATCH_REASONS.get(str(match), ""),
    )
