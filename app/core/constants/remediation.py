"""Remediation plans (Step 16, BUILD_PLAN S44-S56; BLUEPRINT M11): limits, the plan's vocabularies (v1's, word
for word: the approved prompt names them) and request messages."""

from enum import StrEnum
from typing import Final


class Remediation:
    TEXT_MAX_CHARS: Final = 2_000  # one free-text value in a plan's snapshot (BR-REM-01)
    TRUNCATED_MARK: Final = " [truncated]"  # what follows a cut value, so a cut is never silent
    MAX_CONTROL_REFS: Final = 50  # register controls, or a hand-written scenario's controls (BR-REM-02)
    MAX_ACTION_DAYS: Final = 3_650  # one action's duration; above it is capped with a warning (BR-REM-03)
    STATEMENT_MAX_CHARS: Final = 4_000  # a hand-written scenario or risk statement (BR-REM-07)
    NAME_MAX_CHARS: Final = 200  # risk owner, business division, a category name
    TYPE_NAME_MAX_CHARS: Final = 300  # Threat_Type.ThreatTypeName
    THREAT_NAME_MAX_CHARS: Final = 500  # Threat_Catalogue.ThreatName
    JUSTIFICATION_MAX_CHARS: Final = 1_000
    COMMENT_MAX_CHARS: Final = 2_000  # a decision's review comment
    CONTROL_CODE_MAX_CHARS: Final = 100  # Control_Library.ControlCode
    CONTROL_TEXT_MAX_CHARS: Final = 500  # a register control named in free text
    # A rating is exact up to 15 significant digits (what a JSON number holds without rounding), 4 of them
    # after the point: 99,999,999,999.9999 at most (BR-REM-04).
    RATING_MAX_DIGITS: Final = 15
    RATING_DECIMALS: Final = 4
    STRATEGY: Final = "Mitigate"  # the only treatment strategy, set by code (BR-REM-05)
    # A register control the library retired, as the AI reads it: "CII-CID-077 — Firmware review (Integrity)"
    # then this (owner, 2026-10-11: its name and domain, never a bare number).
    RETIRED_MARK: Final = ", retired in the library"
    REASON_MAX_CHARS: Final = 300  # the AI's problems quoted in a failed version's error message


class RiskLevel(StrEnum):
    """The register's own four levels, most urgent first (the urgency ladder of the approved prompt). The
    API accepts any other label too and echoes it; code's urgency checks apply to these four only."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class YesNo(StrEnum):
    YES = "Yes"
    NO = "No"


class ControlCoverage(StrEnum):
    GAPS = "gaps"  # some mapped control is not covered yet: those are the controls to implement
    COVERED = "covered"  # every one is: the actions verify them instead


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
    """Where a hand-written scenario's threat stands in the library (Rule L2): its ids are kept unless a
    curator rejected the wording."""

    ACTIVE = "active"
    PENDING = "pending"  # proposed (now or before), waiting for a curator
    CURATOR_REJECTED = "curator_rejected"  # saved without a library id, never proposed again


class RemediationProgress(StrEnum):
    """A plan's overall progress (#15 `progress.overall`): the first that applies, in this order."""

    FAILED = "failed"  # the latest version failed
    CANCELLED = "cancelled"  # its owner stopped the latest version being written (G214)
    GENERATING = "generating"  # the latest version is queued or running
    AWAITING_REVIEW = "awaiting_review"  # no version decided yet
    REJECTED = "rejected"
    ACCEPTED = "accepted"


class RemediationMessage(StrEnum):
    WINDOW_PAIR = "mitigation_start_date and mitigation_end_date must be sent together."
    WINDOW_ORDER = "mitigation_end_date must be on or after mitigation_start_date."
    # v1's four `_one_kind` refusals (owner, 2026-10-15: one plan request for both kinds of scenario).
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
    CONTROL_NAMED_TWICE = "The same control is named twice ({key}): send one entry per control."
    NAME_WITHOUT_LETTERS = "A name must contain letters or digits."
    CONTROL_UNKNOWN = "No active library control matches {reference}."
    CONTROL_REPEATED = "{reference} names the same control as an earlier entry: send one entry per control."
    CONTROL_ID_CODE_DISAGREE = (
        "control_id {control_id} and control_code {control_code} name two different controls."
    )
    REFERENCES_INVALID = "Some control references cannot be resolved."
    CONTROLS_BEING_MAPPED = (
        "The scenario's controls were still being matched by another job after {seconds} seconds; the plan "
        "job tries again."
    )
    SCENARIO_NOT_FOUND = "Scenario '{scenario_id}' does not exist."
    SCENARIO_OTHER_ENTITY = "Scenario '{scenario_id}' belongs to another entity."
    SCENARIO_NOT_ACCEPTED = "Scenario '{scenario_id}' is not accepted: only an accepted scenario gets a plan."
    PLAN_EXISTS = "Scenario '{scenario_id}' already has a plan ({remediation_id}): regenerate it instead."
    PLAN_NOT_FOUND = "Remediation plan '{remediation_id}' does not exist."
    PLAN_OTHER_ENTITY = "Remediation plan '{remediation_id}' belongs to another entity."
    VERSION_GONE = "Version {version} of remediation plan '{remediation_id}' no longer exists."
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
    # A plan version's own failures (the job's error message).
    PLAN_UNUSABLE = "The AI could not write a usable remediation plan: {reason}"
    PLAN_WITHOUT_ACTION = "The AI's remediation plan has no action, so there is nothing to schedule or do."


class PlanWarning(StrEnum):
    """Every warning the planner's checks and the scheduler add to a plan version (v1's words): where the plan
    and its rules part ways. Warnings never block a plan; the reviewer reads them beside it."""

    # The planner's checks (app/engine/remediation/planner.py, BLUEPRINT M11 R6).
    CONTROL_NOT_IN_LIBRARY = (
        "recommended control {code!r} matched no library control and was removed from the plan"
    )
    CONTROL_IN_REGISTER = (
        "recommended control {code!r} is already in the register (matched by library id) and was removed "
        "from the plan"
    )
    CONTROL_LISTED_TWICE = "recommended control {code!r} is listed more than once — the repeat was removed"
    ALL_COVERED_BUT_GAPS = (
        "every library-mapped control is already in the register (matched by library id) but "
        "control_coverage says 'gaps' — only the free-text register entries could justify that verdict"
    )
    COVERED_WITH_CONTROLS = (
        "controls_to_be_implemented.control_coverage says 'covered' but controls is non-empty"
    )
    COVERED_WITHOUT_LIBRARY = (
        "control_coverage says 'covered' but the scenario has no library-mapped controls — there was nothing "
        "to cover; the verdict is unverifiable"
    )
    URGENCY_NOT_REFLECTED = (
        "risk_level is {level} but no recommended control or action carries Critical/High priority — the "
        "plan's urgency does not reflect the register's scored verdict"
    )
    # The scheduler (app/engine/remediation/scheduler.py, schedule_checks.py; R7).

    DURATION_REPAIRED = (
        "{action}.duration_days {value} is not a whole number of days of at least 1 — scheduled as 1 day"
    )
    DURATION_CAPPED = "{action}.duration_days {days} exceeds {limit} — capped"
    DEPENDENCY_NOT_EARLIER = "{action}.depends_on {reference!r} is not an earlier action — ignored"
    DEPENDENCY_PROSE_EXTRA = "{action}.dependencies mentions {named} but depends_on does not include it"
    DEPENDENCY_PROSE_NONE = "{action}.dependencies says None but it waits for {ids}"
    ACTION_ID_REPEATED = (
        "{action}.action_id {action_id!r} is already used by remediation_action_plan[{position}] — this "
        "action cannot be named as a prerequisite"
    )
    PAST_CALENDAR = (
        "the {total}-day schedule runs past the last representable date: from {anchor} only {fit} days fit, "
        "so the dates at and beyond {last} are clamped and no longer reflect the durations"
    )
    IDS_OUT_OF_SEQUENCE = "action ids are not A1..A{count} in order: {ids}"
    OUT_OF_ORDER = (
        "{action} is listed after work that starts later (day {latest}) although it can start on day {start} "
        "— the sequence is out of order"
    )
    LESS_URGENT_PREREQUISITE = (
        "{prerequisite} ({prerequisite_priority}) is a prerequisite of {action} ({priority}) but is less "
        "urgent than the work it blocks"
    )
    NO_WINDOW = (
        "no mitigation window supplied — the {total}-day schedule is not bounded by a register deadline"
    )
    PAST_WINDOW = "the plan finishes {end}, {days} days after the mitigation window closes ({deadline})"
    STATED_DAYS = "action_plan states {stated} days but the computed critical path is {total} days"
    IMPLEMENTS_UNKNOWN = "{action}.implements_controls names {code!r}, which is not a control of this plan"
    CONTROL_NOT_IMPLEMENTED = "recommended control {code} is not implemented by any action"


class SnapshotWarning(StrEnum):
    """What a plan version's frozen input itself warns about (v1's three register advisories, and a mapped
    control the library no longer holds): flags for the reviewer, never a block."""

    RATING_MISMATCH = (
        "final_risk_rating {final} does not equal likelihood x impact ({likelihood}x{impact}={product}); "
        "register values taken as-is"
    )
    NOT_CALIBRATED = (
        "risk_assessment carries no risk level and no final risk rating — the plan is NOT risk-calibrated"
    )
    WINDOW_OVER = "mitigation window ended {end} — already in the past at plan creation"
    REGISTER_CONTROL_RETIRED = (
        "register control {code} is retired in the library — sent to the AI by its name and domain"
    )
    REGISTER_ID_UNKNOWN = (
        "register control id {control_id} matches no active library control — left out of the plan's input"
    )
    REGISTER_REF_CHANGED = (
        "register control {reference} no longer names one library control (its id and code now name two "
        "rows) — kept as text"
    )
    CONTROL_NO_LONGER_MAPPED = (
        "control {code} was mapped to the scenario for version {version} but is not mapped any more"
    )
    CONTROL_RETIRED = (
        "mapped control {code} is no longer active in the library — left out of the plan's input"
    )


class PlanText(StrEnum):
    """The timeline sentences code writes onto a plan (dates are code's, never the AI's)."""

    DAYS = "{days} day"
    AFTER = ", after {ids} complete"
    DATED = "{start} → {end} ({span}{after})"
    UNDATED = "{span}{after}"
    PLAN_DATED = "{start} → {end} ({total} days, critical path {chain})"
    PLAN_UNDATED = "{total} days in total (critical path {chain})"
