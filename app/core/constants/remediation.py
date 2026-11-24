"""Remediation plans: limits, the vocabularies the approved prompt names, warnings and messages."""

from enum import StrEnum
from typing import Final


class Remediation:
    TEXT_MAX_CHARS: Final = 2_000  # one free-text value in a plan's snapshot
    TRUNCATED_MARK: Final = " [truncated]"  # what follows a cut value, so a cut is never silent
    MAX_CONTROL_REFS: Final = 50  # register controls, or a hand-written scenario's controls
    CONTROLS_CLAIM_SUFFIX: Final = ":plan"  # ends a plan job's controls claim task id (its plan's mapping)
    MAX_ACTION_DAYS: Final = 3_650  # one action's duration; above it is capped with a warning
    STATEMENT_MAX_CHARS: Final = 4_000  # a hand-written scenario or risk statement
    NAME_MAX_CHARS: Final = 200  # risk owner, business division, a category name
    COMMENT_MAX_CHARS: Final = 2_000  # a decision's review comment
    CONTROL_CODE_MAX_CHARS: Final = 100  # Control_Library.ControlCode
    STRATEGY: Final = "Mitigate"  # the only treatment strategy, set by code


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
    READ_ONLY = "read_only"  # no version decided, and its scenario is no longer accepted: nothing to review
    AWAITING_REVIEW = "awaiting_review"  # no version decided yet
    REJECTED = "rejected"
    ACCEPTED = "accepted"


class PlanWarning(StrEnum):
    """What the planner's checks and the scheduler warn about on a plan version; never a block."""

    CONTROL_NOT_IN_LIBRARY = (
        "recommended control {code!r} is not a control of this scenario and was removed from the plan"
    )
    CONTROL_IN_REGISTER = (
        "recommended control {code!r} is already implemented per the register and was removed from the plan"
    )
    GAP_NOT_ADDRESSED = "scenario control {code} is {status} but the plan does not recommend it — this gap stays open"
    CONTROL_UNMATCHED = "control {reference!r} matches no active library control — it covers no scenario control"
    EXISTING_CONTROL_NOT_FOR_THIS_RISK = (
        "existing control {reference!r} is not one of this scenario's library controls or their alternatives — "
        "the plan does not count it against this risk"
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
    NO_WINDOW = "no mitigation window supplied — the {total}-day schedule is not bounded by a register deadline"
    PAST_WINDOW = "the plan finishes {end}, {days} after the mitigation window closes ({deadline})"
    IMPLEMENTS_UNKNOWN = (
        "{action}.implements_controls names {code!r}, which is not a recommended control of this plan — removed"
    )
    CONTROL_NOT_IMPLEMENTED = "recommended control {code} is not implemented by any action"
    CONTROL_NOT_VALIDATED = "control {code} is {validation}, not retained: it is not recommended"
    VALIDATION_NOT_GIVEN = "scenario control {code} was given no relevance check: it is flagged for review"
    REPLACEMENT_REFUSED = (
        "scenario control {code}'s replacement {replacement} is not a library alternative: {code} is flagged for review"
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
    REMEDIATION_TITLE = "{domains} Remediation"
    VERIFICATION_TITLE = "{domains} Verification"
    GAP_FLAGGED = (
        "{code} {name}: its relevance to this risk is unverified, and none of the library alternatives "
        "offered fits better: review it, or search the library for a better control"
    )
    GAP_NONE_VALIDATED = "No identified or alternative library control was confirmed relevant to this risk."
