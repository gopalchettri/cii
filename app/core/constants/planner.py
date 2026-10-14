"""Threat finding and attack paths: limits, outcomes and the plan's messages."""

from enum import StrEnum
from typing import Final


class ThreatFinding:
    """The threat-finding numbers (BLUEPRINT M10 T1-T8), v1's values."""

    SYSTEM_NAME_CHARS: Final = (
        80  # a system's name is shown whole up to this; the alias is what the AI answers
    )
    # The fewest characters of one system's facts it is judged on (a real system's facts run 528-559): below
    # it, after a clip, the plan is refused rather than judge a system by its name.
    MIN_SYSTEM_FACT_CHARS: Final = 150
    ASSET_SHARE_MIN_CHARS: Final = 400  # the asset part of the landscape: max(budget // 4, this)
    #: The landscape line of the organisation's own facts (ContextProperties.ORGANISATION_PREFIX), after the
    #: asset: the relevance and gap-fill rules say it is background only (owner 2026-10-12; G208).
    ORGANISATION_LABEL: Final = "ORGANISATION (the owner's whole estate, background only, NOT this asset): "
    PROMPT_SHARE: Final = 0.8  # a batched prompt fills at most this share of the input limit (room to re-ask)
    GAP_FILL_MAX_CHARS: Final = 3_500  # a gap-fill proposal's type + threat
    LIBRARY_MATCH_CANDIDATES: Final = 10  # hybrid hits reranked against one proposal
    AI_DUPLICATE_COSINE: Final = 0.98  # an AI threat this close to a kept threat is a rewording of it
    CATEGORIES_AT_ONCE: Final = 6  # STRIDE categories judged in parallel
    # Owner, 2026-10-10 (G121): every threat of a category is judged, so batches are kept small and sent at
    # once. A batch's answer time grows with its verdicts (about 1.5 s each on the dev model, measured in
    # S12), so 20 a batch answers in about 30 s, far below the 12,288-token answer limit (about 150 tokens a
    # verdict).
    GATE_BATCH_MAX_ITEMS: Final = 20
    # Gate batches of all six categories share one pool this size (review of S13c: a pool per category let
    # the largest category set the pace, 106 s on the dev asset). It equals the default
    # CII_MAX_CONCURRENT_AI_CALLS; the AI slot limit still caps calls across runs and pods.
    AI_BATCHES_AT_ONCE: Final = 16
    REASON_MAX_CHARS: Final = 500
    LINK_MAX_CHARS: Final = 300
    NOTE_MAX_IDS: Final = 10  # a plan note lists at most this many library ids (the count says the rest)
    MORE_NAMES_LINE_CHARS: Final = 40  # kept free for "... and N more" under the rejected names
    #: The gate's business impact, ranked (higher first).
    IMPACT_RANK: Final[dict[str, int]] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    SYSTEM_ALIAS: Final = "SYS"  # SYS1, SYS2 ... in prompts; never a database id
    RECORD_SLOT: Final = "R"  # R1 ... in the relevance gate
    THREAT_SLOT: Final = "THR"  # THR1 ... in the same-attack check
    # How suitable the gate judged each listed attacker (G229); a listed name it did not rate is LOW.
    SUITABILITY_RANK: Final[dict[str, int]] = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    CHOICE_SLOT: Final = "C"  # C1 ... in the best-threat pick (G209)
    # What a verdict says a threat needs that nothing recorded mentions (G209): kept on the rejection for the
    # reviewer, so only bounded to keep the record small, never a reason to accept.
    NEEDS_MAX_ITEMS: Final = 5
    NEED_MAX_CHARS: Final = 80
    # The best-threat pick (G209): the AI names this many of a group's threats, best first; a group asked in
    # parallel with the others can then still take its next choice when another took its first.
    BEST_PICKS: Final = 3
    PICK_REASON_CHARS: Final = 200  # each candidate's relevance reason, as the pick is shown it


class ActorRole(StrEnum):
    ACTING = "acting"  # carries out the scenario: exactly one per threat
    ALTERNATE = "alternate"  # the next linked actors, best fit first (owner, 2026-10-10)


class AttackerCheck(StrEnum):
    """How a threat's acting attacker was decided (G229: the relevance gate's pick, code's checks)."""

    CHOSEN = "chosen"  # the gate's pick, from the threat's own list, with its reason
    BALANCED = "balanced"  # rated as suitable as the pick and acting for fewer threats in the run
    NONE_FITS = "none_fits"  # the gate found no listed attacker plausible: the nearest acts, flagged
    NOT_CHECKED = "not_checked"  # the gate gave no usable pick: the search ranking decides
    RANKED = "ranked"  # the gate never judged it (an AI threat, a hand-written one): the ranking decides


class GapFillOutcome(StrEnum):
    ACCEPTED = "accepted"
    NONE_APPLIES = "none_applies"  # the AI found no threat the library lacks
    REJECTED = "rejected"  # its proposal failed the relevance gate
    REDUNDANT = "redundant"  # its proposal is a library threat already judged not to apply
    NOT_ASSESSED = "not_assessed"  # the check could not be made: a technical gap, never a verdict
    UNTYPED = "untyped"  # its type matches no library type: a note for a curator, never a threat (G108)
    PREVIOUSLY_REJECTED = "previously_rejected"  # wording a curator rejected or still reviews (G108)


class CandidateRejection(StrEnum):
    """Why a candidate threat of a category was not used (on the category's record)."""

    NOT_RELEVANT = "not_relevant"
    AI_REJECTED = "ai_rejected"
    AI_REDUNDANT = "ai_redundant"
    AI_UNTYPED = "ai_untyped"
    AI_PREVIOUSLY_REJECTED = "ai_previously_rejected"
    NOT_JUDGED = "not_judged"  # the check could not be completed
    # Judged relevant, but only by assuming a component, device or technology nothing recorded mentions
    # (owner 2026-10-12, G209): never planned; the rejection keeps what it needed.
    NEEDS_UNRECORDED = "needs_unrecorded"
    # Judged to apply only where its AssetType cannot be (owner 2026-10-12, G211): an OT threat on an IT
    # system.
    ASSET_TYPE_MISMATCH = "asset_type_mismatch"


class FoldReason(StrEnum):
    """Why a threat was folded into another (no scenario of its own)."""

    SAME_NAME = "same_name"  # an AI threat named like a library threat
    SAME_WORDING = "same_wording"  # an AI threat whose meaning vector matches a kept one
    SAME_ATTACK = "same_attack"  # the AI judged both one attack on the same systems


class PathChoice(StrEnum):
    """Why a path got its rank (v1 path_selection's passes)."""

    CATEGORY_COVERAGE = "category_coverage"
    PATH_COVERAGE = "path_coverage"
    RISK_SIGNIFICANCE = "risk_significance"


class PlanMessage(StrEnum):
    """A plan's refusals and notes, written to be read by a reviewer."""

    SYSTEMS_DO_NOT_FIT = (
        "The asset's {systems} supporting systems leave {share} characters each for their recorded facts in "
        "the model input ({budget} characters), and at least {minimum} are needed to judge a threat against "
        "a system rather than its name. Assess fewer systems at a time."
    )
    ACTOR_LIBRARY_EMPTY = (
        "The threat actor library holds no active actor, so no scenario can name its attacker. Activate at "
        "least one threat actor and start the run again."
    )
    FACTS_SHORTENED = (
        "To fit the AI's input, the recorded facts of {clipped} of {systems} supporting systems were "
        "shortened to {share} characters each (the longest had {longest}); their threats were judged on what "
        "was kept."
    )
    NOT_STRIDE = "Category {category} is not a STRIDE category, so no threat was planned under it."
    THREATS_NOT_JUDGED = (
        "{not_judged} of {threats} threats could not be judged: the AI's answer was still unusable after its "
        "retries."
    )
    GAP_FILL_NOT_ASSESSED = "The AI could not suggest a threat for this category, twice."
    GAP_FILL_NOT_ASKED = (
        "The library check judged {judged} of {records} records, so no AI threat was asked for."
    )
    REPEATS_LIBRARY_THREAT = "Repeats the library threat '{threat}', judged not to apply."
    GAP_FILL_UNTYPED = (
        "The AI suggested '{threat}' of type '{threat_type}', which matches no library type: left for a "
        "curator, never planned."
    )
    REPEATS_REFUSED_WORDING = "Repeats wording a curator rejected or is still reviewing: '{threat}'."
    ASSET_TYPE_MISMATCH = (
        "Its asset type {asset_type} fits none of the places it was judged to apply to: {places}."
    )
    ASSET_TYPE_LEFT_OUT = (
        "{count} library threats were not judged: their asset type ({types}) fits neither the asset nor a "
        "chosen supporting system, which take {takes}."
    )
    ASSET_TYPE_NONE_RECORDED = "only untyped threats (no IT/OT code is recorded for the asset or its systems)"
    ASSET_TYPE_UNKNOWN = (
        "library_data_invalid: {count} live library threats have an asset type that is not IT, OT or IT\\OT "
        "(ids {ids}); each was used as if untyped. A curator must correct it."
    )
    LIBRARY_DATA_INVALID = (
        "library_data_invalid: {count} live library threats have no category link of their own and were left "
        "out (ids {ids}); a curator must link each to its STRIDE category."
    )
    TYPE_CONFLICT_KEPT_APART = (
        "The AI threat '{threat}' ({threat_type}) has the name of the library threat '{library_threat}' "
        "({library_type}) but another type: both kept, never merged (spec v4.0 §7.2.2 step 7)."
    )
    SAME_ATTACK_NOT_CHECKED = (
        "The same-attack check of {threats} threats could not be completed, so none of them was folded."
    )
    BEST_THREAT_NOT_PICKED = (
        "The best threat for {groups} scenario(s) could not be chosen by meaning, so the strongest by impact "
        "and confidence was used."
    )
    ATTACKERS_RANKED_ONLY = (
        "The relevance check gave no usable attacker for {threats} threat(s), so the search ranking chose "
        "their attacker."
    )
    ATTACKER_BALANCED = (
        "{chosen} and {picked} were judged equally suitable ({level}) for this threat; {chosen} acts "
        "because it carries fewer threats in this run."
    )
    # Written set by set, only when asked (owner 2026-10-11): the paths still to write wait for a next set.
    PLAN_NOTE = "{planned} attack paths selected; {written} written, {remaining} still to write, set by set."


class AnswerProblem(StrEnum):
    """Why an AI answer item breaks its contract (app/models/planner_replies.py): quoted to the AI in the
    re-ask, v1's words."""

    GAP_FILL_INCOMPLETE = "AI fallback applies=true requires threat_type, threat and attacker"
    TEXT_REQUIRED = "must not be empty"
    PROBLEMS_REQUIRED = "consistent=false requires at least one problem"
    ENTRY_POINT_NOT_OFFERED = "entry_point must be one of entry_point_options, copied exactly: {options}"
    SYSTEM_REASONS_MISSING = "system_reasons must give one short sentence for each of: {names}"
