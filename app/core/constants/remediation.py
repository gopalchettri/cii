"""Remediation plans: limits, the vocabularies the approved prompt names, warnings and messages."""

from enum import StrEnum
from typing import Final


class Remediation:
    TEXT_MAX_CHARS: Final = 2_000  # one free-text value in a plan's snapshot
    TRUNCATED_MARK: Final = " [truncated]"  # what follows a cut value, so a cut is never silent
    MAX_CONTROL_REFS: Final = 50  # register controls, or a hand-written scenario's controls
    ALTERNATIVES: Final = 5  # library controls offered to replace an identified control that does not fit
    ALTERNATIVE_MATCH: Final = "alternative"  # an alternative's match, beside exact, nearest and given
    MAX_ACTION_DAYS: Final = 3_650  # one action's duration; above it is capped with a warning
    STATEMENT_MAX_CHARS: Final = 4_000  # a hand-written scenario or risk statement
    NAME_MAX_CHARS: Final = 200  # risk owner, business division, a category name
    TYPE_NAME_MAX_CHARS: Final = 300  # Threat_Type.ThreatTypeName
    THREAT_NAME_MAX_CHARS: Final = 500  # Threat_Catalogue.ThreatName
    JUSTIFICATION_MAX_CHARS: Final = 1_000
    COMMENT_MAX_CHARS: Final = 2_000  # a decision's review comment
    CONTROL_CODE_MAX_CHARS: Final = 100  # Control_Library.ControlCode
    CONTROL_TEXT_MAX_CHARS: Final = 500  # a register control named in free text
    RATING_MAX_DIGITS: Final = 15  # a rating is exact up to 15 significant digits (a JSON number) ...
    RATING_DECIMALS: Final = 4  # ... 4 of them after the point
    STRATEGY: Final = "Mitigate"  # the only treatment strategy, set by code
    REASON_MAX_CHARS: Final = 300  # the AI's problems quoted in a failed version's error message
    PROMPT_VERSION: Final = "remediation-3"  # stored on every plan version the prompt writes
    #: The code at the head of a control label ("CID-0477 · Social Engineering"): what the label names.
    LABEL_CODE_PATTERN: Final = r"[^\s·•|:—–]+"
    #: What only code may state in a plan's action_plan: the schedule (a time span, a date, the critical path,
    #: parallel or sequential work, the window, a deadline: code's, from depends_on and duration_days) and the
    #: library (the AI sees only the mapped controls). A maintenance, change or outage window is operations.
    ACTION_PLAN_CLAIM_PATTERN: Final = (
        r"\b(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen"
        r"|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred)"
        r"(?:\s*-\s*|\s+)(?:calendar\s+|working\s+|business\s+)?(?:day|week|month)s?\b"
        r"|\b\d{4}-\d{2}-\d{2}\b|\bcritical[\s-]+path\b|\bdeadlines?\b"
        r"|\b(?<!maintenance\s)(?<!change\s)(?<!outage\s)windows?\b"
        r"|\b(?:parallel|concurrent(?:ly)?|simultaneous(?:ly)?|sequential(?:ly)?|in\s+sequence)\b"
        r"|\blibrar(?:y|ies)\b"
    )
    #: How a recommended control's description says it grows a control already in place.
    EXTENDS_PATTERN: Final = r"\b(?:extend|expand|broaden)"


class YesNo(StrEnum):
    YES = "Yes"
    NO = "No"


class ControlCoverage(StrEnum):
    """Set by code from the controls' implementation status."""

    GAPS = "gaps"  # some scenario control is not, or only partially, implemented
    COVERED = "covered"  # every scenario control is implemented


class ImplementationStatus(StrEnum):
    """Where one scenario control stands against the register on the systems the risk affects, decided by
    code (owner, 2026-10-21)."""

    IMPLEMENTED = "implemented"  # an existing control is on every affected system
    PARTIALLY_IMPLEMENTED = "partially_implemented"  # on some affected systems
    NOT_IMPLEMENTED = "not_implemented"  # on none of them, or not in the register
    UNVERIFIED = "unverified"  # a fallback whose relevance the AI could not confirm: kept for review


class ControlValidation(StrEnum):
    """What the plan's check of an identified control against the scenario's risk decided (owner,
    2026-10-21)."""

    RETAINED = "retained"  # it reduces this risk: kept
    REPLACED = "replaced"  # a library alternative fits clearly better and takes its place
    FLAGGED_FOR_REVIEW = (
        "flagged_for_review"  # not confirmed relevant, nothing better: kept unverified, never recommended
    )


class GapKind(StrEnum):
    """An unresolved gap of a plan, reported apart from its controls."""

    FLAGGED_CONTROL = "flagged_control"  # an identified control kept for review
    NO_VALIDATED_CONTROL = "no_validated_control"  # no control was confirmed relevant to the risk
    UNCOVERED_RISK = "uncovered_risk"  # a part of the risk no checked control reduces (the AI's)


#: The name a status had before 2026-10-21, as older stored plans hold it.
LEGACY_STATUS_NAMES: Final = {"missing": ImplementationStatus.NOT_IMPLEMENTED}


class ControlType(StrEnum):
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class ActionPriority(StrEnum):
    """Most urgent first: the order is the urgency rank."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class LibraryStatus(StrEnum):
    """Where a hand-written scenario's threat stands in the library."""

    ACTIVE = "active"
    PENDING = "pending"  # proposed (now or before), waiting for a curator
    CURATOR_REJECTED = "curator_rejected"  # saved without a library id, never proposed again


class RemediationProgress(StrEnum):
    """A plan's overall progress: the first that applies, in this order."""

    FAILED = "failed"  # the latest version failed
    CANCELLED = "cancelled"  # its owner stopped the latest version being written
    GENERATING = "generating"  # the latest version is queued or running
    AWAITING_REVIEW = "awaiting_review"  # no version decided yet
    REJECTED = "rejected"
    ACCEPTED = "accepted"


class RemediationMessage(StrEnum):
    WINDOW_PAIR = "mitigation_start_date and mitigation_end_date must be sent together."
    WINDOW_ORDER = "mitigation_end_date must be on or after mitigation_start_date."
    MANUAL_NEEDS_SCENARIO = "is_manual=true requires manual_scenario."
    MANUAL_SENDS_NO_IDS = "is_manual=true must not send session_id or scenario_id: TSG creates them."
    GENERATED_NEEDS_IDS = "is_manual=false requires session_id and scenario_id."
    GENERATED_SENDS_NO_SCENARIO = "is_manual=false must not send manual_scenario."
    THREAT_TYPE_REQUIRED = "Name the threat type: send threat_type_id, threat_type_name or both."
    THREAT_REQUIRED = "Name the threat: send threat_id, threat_name or both."
    SCENARIO_NOT_IN_SESSION = "Scenario '{scenario_id}' is not in session '{session_id}'."
    PLAN_NOT_REQUESTED = (
        "No remediation plan has been requested for scenario '{scenario_id}' in session '{session_id}'."
    )
    CONTROL_REF_EMPTY = (
        "A control entry must name the control: send control_id, control_code or control_name."
    )
    SYSTEMS_REQUIRED = (
        "existing_controls[{position}] ({control}) sends no supporting_system_ids: each existing control "
        "lists the supporting systems it is on when existing_controls_all_supporting_system_applicable is 0."
    )
    SYSTEM_NOT_IN_RUN = (
        "{system_id} is not a supporting system of this scenario's run (its systems: {known})."
    )
    REGISTER_SYSTEMS_INVALID = "An existing control names a supporting system the run does not have."
    NAME_WITHOUT_LETTERS = "A name must contain letters or digits."
    CONTROL_UNKNOWN = "No active library control matches {reference}."
    REFERENCES_INVALID = "Some control references cannot be resolved."
    CONTROLS_BEING_MAPPED = (
        "The scenario's controls are being matched by another job; the plan job tries again."
    )
    SCENARIO_NOT_FOUND = "Scenario '{scenario_id}' does not exist."
    SCENARIO_OTHER_ENTITY = "Scenario '{scenario_id}' belongs to another entity."
    SCENARIO_NOT_ACCEPTED = "Scenario '{scenario_id}' is not accepted: only an accepted scenario gets a plan."
    PLAN_EXISTS = "Scenario '{scenario_id}' already has a plan ({remediation_id}): regenerate it instead."
    PLAN_NOT_FOUND = "Remediation plan '{remediation_id}' does not exist."
    PLAN_OTHER_ENTITY = "Remediation plan '{remediation_id}' belongs to another entity."
    VERSION_NOT_FOUND = "Remediation plan '{remediation_id}' has no version {version}."
    NO_DONE_VERSION = "Remediation plan '{remediation_id}' has no finished version to decide yet."
    NOT_COMPLETE = (
        "Version {version} of remediation plan '{remediation_id}' is {status}: only a done version is "
        "decided."
    )
    PLAN_READ_ONLY = (
        "Scenario '{scenario_id}' is no longer accepted, so its remediation plan is read-only: request a "
        "plan for the accepted version instead."
    )
    VERSION_IN_PROGRESS = (
        "Version {version} of remediation plan '{remediation_id}' is still being written: regenerate it once "
        "it is done or failed."
    )
    VERSION_LIMIT_REACHED = (
        "Remediation plan '{remediation_id}' already has {max_versions} versions, the most one plan keeps "
        "(REGENERATIONS_MAX_VERSION_COUNT): accept or reject one of them instead of regenerating."
    )
    CHANGED_CONCURRENTLY = (
        "Remediation plan '{remediation_id}' changed while this decision was made: read it again."
    )
    IDEMPOTENCY_KEY_REQUIRED = "A hand-written scenario needs an Idempotency-Key header."
    THREAT_REFS_INVALID = "The threat, its type or its category does not match the library."
    UNKNOWN_ID = "No live or pending library row has id {id}."
    ID_NAME_DISAGREE = "Id {id} is the library's '{library_name}', not '{name}'."
    TYPE_MISMATCH = "The library files '{threat}' under the type '{library_type}'."
    CATEGORY_UNKNOWN = "'{name}' is not a STRIDE category."
    CATEGORY_NOT_OF_THREAT = "The library files '{threat}' under {categories}, not '{category}'."
    PLAN_UNUSABLE = "The AI could not write a usable remediation plan: {reason}"  # a version's own failure
    PLAN_WITHOUT_ACTION = "The AI's remediation plan has no action, so there is nothing to schedule or do."
    # The re-ask's problems: what the AI's first answer got wrong about the gaps.
    GAP_REQUIRED = "controls_to_be_implemented must include {code}: it is {status} for this scenario"
    VALIDATION_MISSING = (
        "control_validation must give one entry for {code}: retained, replaced or flagged_for_review"
    )
    REPLACEMENT_REQUIRED = "{code} is replaced: give its replacement_code, one of library_alternatives"
    REPLACEMENT_UNKNOWN = "{code} is replaced by {replacement}, which is not one of library_alternatives"
    NOT_VALIDATED_LISTED = (
        "{code} is {validation}: remove it from controls_to_be_implemented and from every implements_controls"
    )
    IMPLEMENTED_LISTED = (
        "{code} is already implemented: remove it from controls_to_be_implemented and from every "
        "implements_controls"
    )
    CODE_FACT_IN_ACTION_PLAN = (
        "action_plan states '{claim}': restate no schedule (order, parallel work, days, dates, critical "
        "path, window or deadline) and say nothing of the library — the application owns both"
    )
    PARTIAL_NOT_EXTENDED = (
        "{code} is partially implemented: describe what to extend and where, never a new deployment"
    )
    MISSING_EXTENDED = "{code} is on no affected system yet: describe implementing it, not extending it"
    INTERIM_WHEN_COVERED = (
        "{action} is an interim action, but every control is implemented: when covered, actions only verify, "
        "test or evidence the implemented controls"
    )


class PlanWarning(StrEnum):
    """What the planner's checks and the scheduler warn about on a plan version; never a block."""

    CONTROL_NOT_IN_LIBRARY = (
        "recommended control {code!r} is not a control of this scenario and was removed from the plan"
    )
    CONTROL_IN_REGISTER = (
        "recommended control {code!r} is already implemented per the register and was removed from the plan"
    )
    GAP_NOT_ADDRESSED = (
        "scenario control {code} is {status} but the plan does not recommend it — this gap stays open"
    )
    CONTROL_UNMATCHED = (
        "control {reference!r} matches no active library control — it covers no scenario control"
    )
    CONTROL_LISTED_TWICE = "recommended control {code!r} is listed more than once — the repeat was removed"
    DURATION_REPAIRED = (
        "{action}.duration_days {value} is not a whole number of days of at least 1 — scheduled as 1 day"
    )
    DURATION_CAPPED = "{action}.duration_days {days} exceeds {limit} — capped"
    DEPENDENCY_NOT_EARLIER = "{action}.depends_on {reference!r} is not an earlier action — ignored"
    ACTION_ID_REPEATED = (
        "{action}.action_id {action_id!r} is already used by remediation_action_plan[{position}] — this "
        "action cannot be named as a prerequisite"
    )
    PAST_CALENDAR = (
        "the {total}-day schedule runs past the last representable date: from {anchor} only {fit} fit, "
        "so the dates at and beyond {last} are clamped and no longer reflect the durations"
    )
    NO_WINDOW = (
        "no mitigation window supplied — the {total}-day schedule is not bounded by a register deadline"
    )
    PAST_WINDOW = "the plan finishes {end}, {days} after the mitigation window closes ({deadline})"
    IMPLEMENTS_UNKNOWN = (
        "{action}.implements_controls names {code!r}, which is not a recommended control of this plan — "
        "removed"
    )
    CONTROL_NOT_IMPLEMENTED = "recommended control {code} is not implemented by any action"
    CONTROL_NOT_VALIDATED = "control {code} is {validation}, not retained: it is not recommended"
    VALIDATION_NOT_GIVEN = "scenario control {code} was given no relevance check: it is flagged for review"
    REPLACEMENT_REFUSED = (
        "scenario control {code}'s replacement {replacement} is not a library alternative: {code} is "
        "flagged for review"
    )
    ACTION_SYSTEM_UNKNOWN = "{action} names '{system}', not a supporting system the risk affects: left out"


class PlanText(StrEnum):
    """The timeline sentences code writes onto a plan (dates are code's, never the AI's)."""

    DAYS = "{days} day"  # code adds the "s": "1 day", "2 days"
    AFTER = ", after {ids} complete"
    DATED = "{start} → {end} ({span}{after})"
    UNDATED = "{span}{after}"
    PLAN_DATED = "{start} → {end} ({total}, critical path {chain})"
    PLAN_UNDATED = "{total} in total (critical path {chain})"
    # The plan's title, from the library domains of the controls it recommends, or verifies when covered.
    REMEDIATION_TITLE = "{domains} Remediation"
    VERIFICATION_TITLE = "{domains} Verification"
    # The unresolved gaps code reports.
    GAP_FLAGGED = "{code} {name}: its relevance to this risk is unverified and no library control fits better"
    GAP_NONE_VALIDATED = "No identified or alternative library control was confirmed relevant to this risk."
