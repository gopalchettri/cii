"""Scenario writing (Step 12): a scenario's writing outcome, its findings and their severities, its route and
the plan check (approved prompts, docs/SCENARIO_PROMPTS_DRAFT.md v2; spec v4.0 §7.4.6-7.4.7)."""

from enum import StrEnum
from typing import Final


class Writing:
    # The plan check's problems kept as notes: one per plan-check rule at most is expected; a longer list or
    # problem is cut, so a runaway answer never bloats a scenario or the rewrite prompt.
    MAX_PLAN_PROBLEMS: Final = 10
    PROBLEM_MAX_CHARS: Final = 300
    # In "why it applies", a system this scenario is not on (each has its own path: G208) is named as
    # OTHER_SYSTEM, and two or more of them in a row as OTHER_SYSTEMS.
    OTHER_SYSTEM: Final = "another supporting system"
    OTHER_SYSTEMS: Final = "other supporting systems"


class ScenarioStatus(StrEnum):
    """tsg_scenarios.status: how writing one path's scenario ended. The path's own outcome (served, attempts,
    abandoned at Generation.MAX_PATH_ATTEMPTS) lives on the plan."""

    DONE = "done"  # written: served and counted
    FAILED = "failed"  # the writer's answer stayed unreadable: a visible failure card; the path is retried
    # A blocker was still there after the one rewrite: kept for audit only, never served, counted or
    # accepted (spec v4.0 §7.4.7); the path is tried again like a failure.
    BLOCKED = "blocked"


class ScenarioOutcome(StrEnum):
    """tsg_scenarios_total{outcome}: what each save settled for its path."""

    WRITTEN = "written"
    BLOCKED = "blocked"
    FAILED = "failed"
    ABANDONED = "abandoned"  # counted once more, when the path's last attempt failed


class FindingSeverity(StrEnum):
    BLOCKER = "blocker"  # an exact code fault: the scenario is blocked
    WARNING = "warning"  # shown on the scenario (validation.status "warning"); it never blocks an accept
    NOTE = "note"  # information only: the plan check's words


class FindingCode(StrEnum):
    """What a code rule or the plan check found in a written scenario
    (engine/scenarios/writing/exact_rules.py)."""

    UNKNOWN_ID = "unknown_id"  # an internal label (SYS1, THR2 ...) the brief never contains
    UNCITED_ADVISORY_ID = "uncited_advisory_id"  # an advisory number (CVE, ICSA ...) no intelligence supplied
    ASSET_NOT_IN_STATEMENT = "asset_not_in_statement"
    ASSET_NOT_IN_RISK = "asset_not_in_risk"
    ATTACKER_NOT_NAMED = "attacker_not_named"
    OTHER_ATTACKER_NAMED = "other_attacker_named"
    SYSTEM_OUT_OF_SCOPE = "system_out_of_scope"
    SYSTEM_LINK_CLAIMED = "system_link_claimed"
    PLAN_CHECK = "plan_check"
    PLAN_CHECK_NOT_MADE = "plan_check_not_made"


#: Which findings block a scenario: only exact code faults do (owner C5; spec v4.0 §7.4.7 "application code
#: defines which codes block serving/counting").
FINDING_SEVERITIES: Final[dict[FindingCode, FindingSeverity]] = {
    FindingCode.UNKNOWN_ID: FindingSeverity.BLOCKER,
    FindingCode.UNCITED_ADVISORY_ID: FindingSeverity.BLOCKER,
    FindingCode.ASSET_NOT_IN_STATEMENT: FindingSeverity.WARNING,
    FindingCode.ASSET_NOT_IN_RISK: FindingSeverity.WARNING,
    FindingCode.ATTACKER_NOT_NAMED: FindingSeverity.WARNING,
    FindingCode.OTHER_ATTACKER_NAMED: FindingSeverity.WARNING,
    FindingCode.SYSTEM_OUT_OF_SCOPE: FindingSeverity.WARNING,
    FindingCode.SYSTEM_LINK_CLAIMED: FindingSeverity.WARNING,
    FindingCode.PLAN_CHECK: FindingSeverity.NOTE,
    FindingCode.PLAN_CHECK_NOT_MADE: FindingSeverity.NOTE,
}


class FindingMessage(StrEnum):
    """What a finding says: shown to the reviewer, and listed to the writer in the one rewrite."""

    UNKNOWN_ID = "Names {labels}: internal labels the platform never gave this scenario. Remove them."
    UNCITED_ADVISORY_ID = "Cites {ids}, which no threat intelligence supplied. Remove the advisory numbers."
    ASSET_NOT_IN_STATEMENT = "The scenario statement does not name the asset ({asset})."
    ASSET_NOT_IN_RISK = "The risk statement does not name the asset ({asset})."
    ATTACKER_NOT_NAMED = (
        "The scenario statement does not name its attacker ({attacker}) as a type of attacker."
    )
    OTHER_ATTACKER_NAMED = "Names another attacker: {names}. Name only {attacker}."
    SYSTEM_OUT_OF_SCOPE = "Names a system outside this scenario: {names}."
    SYSTEM_LINK_CLAIMED = "Claims a link between {systems}, which the platform does not record."
    PLAN_CHECK_NOT_MADE = "The plan check could not be made: {reason}"


class Route(StrEnum):
    """content.route.status, set by code (spec v4.0 §7.4.6): the platform records no link between two
    systems, so no route is ever `validated` or `assumed`."""

    STANDALONE = "standalone"  # the scenario claims no link between systems
    UNKNOWN = "unknown"  # it relies on a system-to-system link the platform does not record


class PlanCheckStatus(StrEnum):
    CONSISTENT = "consistent"
    INCONSISTENT = "inconsistent"  # its problems are notes on the scenario
    UNCHECKED = "unchecked"  # the check could not be made: a note says so


class PathProblem(StrEnum):
    """Why a planned path cannot be written (PathNotWritable): checked before any AI call."""

    NOT_ONE_THREAT = "it is not exactly one threat of the plan"
    CATEGORY_UNKNOWN = "its category is not a STRIDE category"
    THREAT_UNNAMED = "its threat has no type or no name"
    NO_ACTING_ATTACKER = "its threat has no acting attacker"
    SYSTEM_NOT_IN_RUN = "one of its systems is not a system of the run"
    THREAT_RETIRED = "its threat is no longer active in the library"
    ATTACKER_RETIRED = "its acting attacker is no longer active in the library"
