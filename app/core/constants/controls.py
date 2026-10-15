"""Controls for a written scenario (Step 13, BUILD_PLAN S31-S34; spec v4.0 §7.5): the compatible pool, how
many to search, the cut-off match labels, and the per-scenario lease and retries."""

from enum import StrEnum
from typing import Final

from app.core.constants.library import AssetType
from app.core.constants.runs import Generation


class Controls:
    QUERY_MAX_CHARS: Final = 4_000  # one scenario's control query, cut from the end
    QUERY_MITIGATIONS: Final = 6  # G234: the cited evidence's mitigations the query's head carries
    # G243 (owner 2026-10-14): a control of this library domain is mapped only to a card whose threat type or
    # name says it is about AI ("AI Abuse", "personal GenAI data leakage"); acronyms match case-sensitively.
    AI_DOMAIN: Final = "Artificial Intelligence & Autonomous Technologies"
    AI_THREAT_WORDS: Final = (
        r"\b(?:AI|GenAI|LLMs?|ML)\b|(?i:artificial intelligence|machine learning|large language model)"
    )
    MAX_ATTEMPTS: Final = 5  # then failed; the sweep tries again after RETRY_FAILED_AFTER_SECONDS
    LEASE_SECONDS: Final = 120  # one scenario's mapping, and a run's delivery (G195), renewed while it runs
    # A plan job whose scenario another job maps now waits for that mapping, checking this often, at most
    # LEASE_SECONDS (G262): a retry would spend one of its few attempts on waiting.
    PLAN_WAIT_POLL_SECONDS: Final = 5
    RETRY_FAILED_AFTER_SECONDS: Final = 1_800
    SWEEP_EVERY_SECONDS: Final = 300
    RESEND_QUEUED_AFTER_SECONDS: Final = 600  # a queued mapping no worker took: its message was lost
    # Mappings one delivery makes before the run's next turn is queued behind whatever waits: a writer's
    # batch, so a batch of writing and a batch of mapping take turns on a worker thread.
    PER_DELIVERY: Final = Generation.WRITER_BATCH


class ControlMessage(StrEnum):
    NEAREST_ONLY = (
        "No control reached the control similarity threshold of {cutoff:g}; the nearest compatible "
        "controls are kept, up to the minimum of {least}."
    )
    # Each control's rationale and the mapping's audit (owner 2026-10-13, G225).
    STRONG_REASON = "Score {score:.0f} is at or above the threshold of {cutoff:g}: strong."
    FALLBACK_REASON = (
        "Score {score:.0f} is below the threshold of {cutoff:g}: fallback, among the nearest kept to reach "
        "the minimum of {least}."
    )
    SHORTFALL = "{kept} control(s) kept: the minimum is {least}, but only {kept} compatible control(s) exist."
    LEFT_OUT = "{count} more control(s) reached the threshold; MAX_CONTROLS keeps the best {most}."
    # Owner 2026-10-15 ("provide the near possible control"): never no control for lack of the asset's type.
    OTHER_TYPE = (
        "No control of asset type(s) {types} exists; the nearest control(s) of another type are kept: check "
        "that they fit."
    )


class ControlMatch(StrEnum):
    EXACT = "exact"  # scored at or above the reranker's control cut-off
    NEAREST = "nearest"  # none reached it: the single best compatible control, with a warning
    GIVEN = "given"  # named by the person for a hand-written scenario (Rule R2), in the order given


#: Why a control was kept for a scenario, in words (the results' match_reason).
#: The selection tier each match is (owner 2026-10-13, G225): "strong" or "fallback"; a named one is "given".
CONTROL_TIERS: Final[dict[str, str]] = {
    ControlMatch.EXACT: "strong",
    ControlMatch.NEAREST: "fallback",
    ControlMatch.GIVEN: "given",
}
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
