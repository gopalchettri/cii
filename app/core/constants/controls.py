"""Controls for a written scenario (Step 13, BUILD_PLAN S31-S34; spec v4.0 §7.5): the compatible pool, how
many to search, the cut-off match labels, and the per-scenario lease and retries."""

from enum import StrEnum
from typing import Final

from app.core.constants.library import AssetType
from app.core.constants.runs import Generation


class Controls:
    SHORTLIST: Final = 40  # library controls the search hands the reranker for one scenario
    QUERY_MAX_CHARS: Final = 4_000  # one scenario's control query, cut from the end
    MAX_ATTEMPTS: Final = 5  # then failed; the sweep tries again after RETRY_FAILED_AFTER_SECONDS
    LEASE_SECONDS: Final = 120  # one scenario's mapping, and a run's delivery (G195), renewed while it runs
    RETRY_FAILED_AFTER_SECONDS: Final = 1_800
    SWEEP_EVERY_SECONDS: Final = 300
    RESEND_QUEUED_AFTER_SECONDS: Final = 600  # a queued mapping no worker took: its message was lost
    # Mappings one delivery makes before the run's next turn is queued behind whatever waits: a writer's
    # batch, so a batch of writing and a batch of mapping take turns on a worker thread.
    PER_DELIVERY: Final = Generation.WRITER_BATCH


class ControlMessage(StrEnum):
    NEAREST_ONLY = (
        "No control reached the control similarity threshold of {cutoff:g}; the single nearest compatible "
        "control is kept."
    )


class ControlMatch(StrEnum):
    EXACT = "exact"  # scored at or above the reranker's control cut-off
    NEAREST = "nearest"  # none reached it: the single best compatible control, with a warning
    GIVEN = "given"  # named by the person for a hand-written scenario (Rule R2), in the order given


#: Why a control was kept for a scenario, in words (the results' match_reason).
CONTROL_MATCH_REASONS: Final[dict[str, str]] = {
    ControlMatch.EXACT: "Scored at or above the control similarity threshold for this scenario.",
    ControlMatch.NEAREST: "No control reached the threshold; this is the nearest relevant library control.",
    ControlMatch.GIVEN: "Named by the person who wrote this scenario.",
}


#: Which library AssetType values (Threat_Catalogue, Control_Library) fit an asset or system of each category
#: code (owner 2026-10-12, G211: IT\OT is both). A row with no AssetType, or one that is not a value, fits
#: everywhere (models/library.asset_type_fits).
COMPATIBLE_ASSET_TYPES: Final[dict[str, frozenset[str]]] = {
    AssetType.IT: frozenset({AssetType.IT, AssetType.IT_OT}),
    AssetType.OT: frozenset({AssetType.OT, AssetType.IT_OT}),
    AssetType.IT_OT: frozenset({AssetType.IT, AssetType.OT, AssetType.IT_OT}),
}
