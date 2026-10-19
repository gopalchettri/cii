"""Written scenarios: their writing outcome and findings, the review calls and the results format."""

from enum import StrEnum
from typing import Final


class Writing:
    MAX_PLAN_PROBLEMS: Final = 10  # the plan check's problems kept as notes ...
    PROBLEM_MAX_CHARS: Final = 300  # ... each cut to this
    OTHER_SYSTEM: Final = "another supporting system"  # a system this scenario is not on, in "why it applies"
    OTHER_SYSTEMS: Final = "other supporting systems"  # two or more of them in a row
    SCENARIO_WORDS_SLOT: Final = "<scenario words>"  # the prompts' slot for THREAT_SCENARIO_WORD_LIMIT
    RISK_WORDS_SLOT: Final = "<risk words>"  # the prompts' slot for RISK_STATEMENT_WORD_LIMIT
    EVIDENCE_WORDS_SLOT: Final = "<evidence words>"  # the prompts' slot for EVIDENCE_STATEMENT_WORD_LIMIT


class ScenarioStatus(StrEnum):
    """tsg_scenarios.status: how writing one path's scenario ended."""

    DONE = "done"  # written: served and counted
    FAILED = "failed"  # the writer's answer stayed unreadable: a visible failure card; the path is retried
    BLOCKED = "blocked"  # a blocker was found: kept for audit only; the path is retried


class ScenarioOutcome(StrEnum):
    """tsg_scenarios_total{outcome}: what each save settled for its path."""

    WRITTEN = "written"
    BLOCKED = "blocked"
    FAILED = "failed"
    ABANDONED = "abandoned"  # counted once more, when the path's last attempt failed


class FindingSeverity(StrEnum):
    BLOCKER = "blocker"  # a spec or safety failure: the scenario is blocked
    WARNING = "warning"  # shown on the scenario; it never blocks an accept
    NOTE = "note"  # information (validation_notes): the plan check's words


class FindingCode(StrEnum):
    """What an exact check or the reviewer found in a written scenario."""

    UNKNOWN_ID = "unknown_id"  # an internal label (SYS1, THR2 ...) the brief never contains
    UNCITED_ADVISORY_ID = "uncited_advisory_id"  # an advisory number (CVE, ICSA ...) no intelligence supplied
    PLAN_CHECK = "plan_check"  # a rule the reviewer says is broken: a note for review
    PLAN_CHECK_NOT_MADE = "plan_check_not_made"
    SCENARIO_MISMATCH = "scenario_mismatch"  # the statement carries out another threat, or the risk another
    CITATION_REMOVED = "citation_removed"  # the writer's passage not cited: code's own sentence instead
    NO_EVIDENCE_CITED = "no_evidence_cited"  # stored on older scenarios: a story citing none of its sources
    NEAR_DUPLICATE = "near_duplicate"  # the same path, or the very same words, as a scenario already held


class FindingMessage(StrEnum):
    """What a finding says: stored on the scenario and shown with it."""

    UNKNOWN_ID = "Names {labels}: internal labels the platform never gave this scenario. Remove them."
    UNCITED_ADVISORY_ID = "Cites {ids}, which no threat intelligence supplied. Remove the advisory numbers."
    PLAN_CHECK_NOT_MADE = "The plan check could not be made: {reason}"
    CITATION_REMOVED = (
        "The writer's evidence passage was not cited ({reason}): the platform cites its own precedent "
        "sentence from the same source instead."
    )
    SCENARIO_MISMATCH = (
        "The reviewer found that the scenario no longer describes the plan's {parts}: the statement and the "
        "risk must carry out the plan's own threat and its consequence."
    )
    NEAR_DUPLICATE = (
        "Tells the same event as scenario {scenario_id}: the same threat on the same systems and kind, or "
        "the very same words."
    )


#: How strongly each finding is enforced: a blocker keeps the scenario from being served.
FINDING_SEVERITIES: Final[dict[FindingCode, FindingSeverity]] = {
    FindingCode.UNKNOWN_ID: FindingSeverity.BLOCKER,
    FindingCode.UNCITED_ADVISORY_ID: FindingSeverity.BLOCKER,
    FindingCode.PLAN_CHECK: FindingSeverity.NOTE,
    FindingCode.PLAN_CHECK_NOT_MADE: FindingSeverity.WARNING,
    FindingCode.SCENARIO_MISMATCH: FindingSeverity.BLOCKER,
    FindingCode.CITATION_REMOVED: FindingSeverity.WARNING,
    FindingCode.NO_EVIDENCE_CITED: FindingSeverity.BLOCKER,
    FindingCode.NEAR_DUPLICATE: FindingSeverity.BLOCKER,
}

#: A scenario blocked by one of these is final: no new attempt can change it, so its path is given up.
FINAL_FINDINGS: Final[frozenset[FindingCode]] = frozenset({FindingCode.NEAR_DUPLICATE})


class Route(StrEnum):
    """content.route.status: the platform records no link between two systems."""

    STANDALONE = "standalone"  # the scenario claims no link between systems
    UNKNOWN = "unknown"  # it relies on a system-to-system link the platform does not record


class PlanCheckStatus(StrEnum):
    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"  # its problems are notes on the scenario
    UNCHECKED = "unchecked"  # not made: an exact check blocks, or its answer stayed unusable (a warning)


class PathProblem(StrEnum):
    """Why a planned path cannot be written (PathNotWritable): checked before any AI call."""

    NOT_ONE_THREAT = "it is not exactly one threat of the plan"
    CATEGORY_UNKNOWN = "its category is not a STRIDE category"
    THREAT_UNNAMED = "its threat has no type or no name"
    NO_ACTING_ATTACKER = "its threat has no acting attacker"
    ATTACKER_UNSUPPORTED = (
        "no attacker fits its threat: the relevance check found none plausible, none reached the "
        "relevance threshold, or no check judged the nearest one, so none is attributed"
    )
    SYSTEM_NOT_IN_RUN = "one of its systems is not a system of the run"
    THREAT_RETIRED = "its threat is no longer active in the library"
    ATTACKER_RETIRED = "its acting attacker is no longer active in the library"


class Review:
    MAX_IDS_PER_CALL: Final = 50  # scenario ids per accept, reject or regenerate call
    MAX_ID_CHARS: Final = 64  # a scenario id is a 36-character uuid: a longer one is refused (422)


class TargetProblem(StrEnum):
    """Why one scenario id of a review call is refused (`errors[].reason`) or skipped (`skipped[].reason`)."""

    UNKNOWN = "unknown"  # not a served scenario of this run
    FAILURE_SCENARIO = "failure_scenario"  # a failure card: the write job retries its path
    ALREADY_REJECTED = "already_rejected"  # decisions are final; regenerate to get a new version
    ALREADY_ACCEPTED = "already_accepted"
    DUPLICATE_VERSION = "duplicate_version"  # two versions of one path, or another version already accepted
    LIBRARY_INACTIVE = "library_inactive"  # its library threat was retired after it was written
    VERSION_NOT_CURRENT = "version_not_current"  # a newer version replaced it: regenerate the newest one
    CHANGED_CONCURRENTLY = (
        "changed_concurrently"  # another call decided it between this call's read and write
    )
    HAND_WRITTEN = "hand_written"  # a person wrote it: there is no plan path to write it again


class PromotionOutcome(StrEnum):
    """What promoting one AI-proposed threat did."""

    INSERTED = "inserted"  # written to the library as pending: a curator approves or rejects it
    EXISTING = "existing"  # the library already has it, live or pending: nothing written
    CURATOR_REJECTED = "curator_rejected"  # a curator rejected this wording: never proposed again


class ReviewMessage(StrEnum):
    IDS_REPEATED = "Each scenario may be sent only once."
    GENERATION_IN_PROGRESS = "Run '{session_id}' is still generating: try again once it is done."
    RUN_FAILED = "Run '{session_id}' failed before any scenario was written."
    RUN_CANCELLED = (
        "Run '{session_id}' was cancelled before its scenarios were planned: start a new run for its asset."
    )
    NOT_DECIDABLE = "Some scenarios cannot be {decision}."
    NOT_REGENERABLE = "Some scenarios cannot be regenerated."
    NOTHING_TO_ACCEPT = "Run '{session_id}' has no written scenario to accept."
    ANOTHER_VERSION_ACCEPTED = (
        "Another version of the same attack path is already accepted: send replace_accepted to replace it."
    )
    NOTHING_LEFT = "Every selected attack path of run '{session_id}' is written."
    TARGET_REACHED = (
        "Every selected attack path of run '{session_id}' is written; the others were left out by "
        "TOTAL_SCENARIO_COUNT."
    )
    SCENARIOS_ABANDONED = "Every attack path of run '{session_id}' left to write was given up."
    ASSET_BUSY = "Asset {asset_id} has another active run: try again once it is done."
    SCENARIO_NOT_ACCEPTED = "Scenario '{scenario_id}' is not accepted: accept it before promoting its threat."
    NOTHING_TO_PROMOTE = "Scenario '{scenario_id}' is built on a library threat: there is nothing to promote."


class ThreatSource(StrEnum):
    """Where a generated scenario's threat (and its type) came from; None on a hand-written card."""

    LIBRARY = "LIBRARY"
    AI_PROPOSED = "AI_PROPOSED"


class ScopeType(StrEnum):
    ASSET = "ASSET"  # the asset itself, through no supporting system
    SYSTEM = "SYSTEM"  # one supporting system
    COMBINATION = "COMBINATION"  # more than one


class ReviewFlag(StrEnum):
    """What a reviewer should look at on a card, in order of listing."""

    AI_PROPOSED_TYPE = "AI_PROPOSED_TYPE"
    AI_PROPOSED_THREAT = "AI_PROPOSED_THREAT"
    ASSUMED_ROUTE = "ASSUMED_ROUTE"
    VALIDATION_EXCEPTION = "VALIDATION_EXCEPTION"  # a warning, or a failure card
    PLAN_CHECK = "PLAN_CHECK"  # the plan check kept a note
    NEAREST_CONTROL = "NEAREST_CONTROL"
    CONTROL_LIBRARY_GAP = "CONTROL_LIBRARY_GAP"


class ControlMatchStatus(StrEnum):
    EXACT = "EXACT"  # at least one control reached the cut-off
    NEAREST_ONLY = "NEAREST_ONLY"  # none did: the nearest are offered
    CONTROL_LIBRARY_GAP = "CONTROL_LIBRARY_GAP"  # mapped, and no control fits
    PENDING = "PENDING"  # not mapped yet


class LibraryOutcome(StrEnum):
    """Where a hand-written scenario's threat (and its type) stands in the threat library."""

    EXISTING = "existing"
    INSERTED = "inserted"  # proposed, waiting for a curator
    NOT_PROPOSED = "not_proposed"
    REJECTED_BY_CURATOR = "rejected_by_curator"


class LibraryBanner(StrEnum):
    """The sentence for the person about a hand-written threat's library outcome."""

    REJECTED = (
        "A curator reviewed '{name}' and declined it, so this scenario keeps your wording but is not "
        "linked to the threat library. Sending it again will not re-propose it: choose a different name if "
        "you want a library entry."
    )
    PROPOSED = (
        "Proposed to the threat library and awaiting a curator's review. The scenario is saved either "
        "way; it becomes verified only if the curator approves."
    )


class ActionStatus(StrEnum):
    """What a next-set or regenerate call started."""

    GENERATING = "generating"  # a next set: more scenarios are being written
    REGENERATING = "regenerating"  # new versions of chosen scenarios
    MAPPING_CONTROLS = "mapping_controls"  # a next set that only resumed stopped controls


class PlanStage(StrEnum):
    """Where a candidate left the plan (plan_trace.drops[].stage), in planning order."""

    PRE_FILTER = "pre_filter"  # before the gate: its type fits no place, or it links no attacker
    GATE = "gate"  # the relevance gate's verdict, or its batch was skipped
    CHECKS = "checks"  # code's checks on the verdicts: the asset-type fit, a need refused elsewhere
    GAP_FILL = "gap_fill"  # the AI's proposal for a kind with nothing accepted, not kept
    MERGE = "merge"  # folded into another threat, or a merged kind fitting no place
    ATTACKER = "attacker"  # no acting attacker
    HELD = "held"  # the asset already holds this threat as this kind


class PlanLoss(StrEnum):
    """Why a candidate left the plan, beside CandidateRejection and AttackerCheck."""

    TYPE_FITS_NO_PLACE = "type_fits_no_place"
    NO_LINKED_ACTOR = "no_linked_actor"
    NOT_JUDGED = "not_judged"  # its gate batch was skipped
    NEEDS_UNRECORDED_ELSEWHERE = "needs_unrecorded_elsewhere"  # a need found under another kind
    MERGED = "merged"
    ALREADY_HELD = "already_held"
    LIBRARY_REPEAT = "library_repeat"  # a gap-fill proposal that is a library threat already judged
    TYPE_UNMATCHED = "type_unmatched"  # a gap-fill proposal whose type matches no library type


class PlanTraceLimits:
    MAX_DROPS: Final = 300  # drops listed on a trace; its counts are always whole
    DETAIL_MAX_CHARS: Final = 160
    ASSET_ITSELF: Final = "the asset itself"  # the turn and group of a path on no supporting system


class PlanTraceMessage(StrEnum):
    NOT_PLANNED = (
        "Session '{session_id}' has no plan trace: it is not planned yet, or it was planned before plan "
        "traces were kept."
    )


#: content.route.status in results words: a route on an unrecorded link between systems is ASSUMED.
ROUTE_WORDS: Final[dict[str, str]] = {"standalone": "STANDALONE", "unknown": "ASSUMED"}
CONTROLS_EXHAUSTED: Final = "retry_budget_exhausted"  # the controls job gave up after its tries
SCOPE_ASSET_KEY: Final = "A"
