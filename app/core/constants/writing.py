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
    # One sentence per supporting system on a card: why the scenario applies to it or not (G216); a longer
    # one is cut.
    SYSTEM_REASON_MAX_CHARS: Final = 300
    # Where the writers' prompts take THREAT_SCENARIO_WORD_LIMIT and RISK_STATEMENT_WORD_LIMIT (G226): the
    # approved text holds these slots, filled from the settings when a prompt is built.
    SCENARIO_WORDS_SLOT: Final = "<scenario words>"
    RISK_WORDS_SLOT: Final = "<risk words>"
    # A text outside its range by more than this is a finding (the writer rewrites it once): under half the
    # minimum, or over the maximum by a tenth (the margin the story check used since G219).
    WORDS_BELOW_SHARE: Final = 0.5
    WORDS_ABOVE_SHARE: Final = 1.1


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
    STATEMENT_LENGTH = "statement_length"  # far outside THREAT_SCENARIO_WORD_LIMIT (G226)
    RISK_LENGTH = "risk_length"  # far outside RISK_STATEMENT_WORD_LIMIT (G226)
    # G229 (owner 2026-10-13), external intelligence on: a story that cites no evidence, a citation with no
    # claim, a citation its entry does not support.
    NO_EVIDENCE_CITED = "no_evidence_cited"
    CITATION_REMOVED = "citation_removed"  # G252: a footnote its source did not support was taken out
    EVIDENCE_LINK_MISSING = "evidence_link_missing"
    CITATION_UNSUPPORTED = "citation_unsupported"
    # G229, both writers: the scenario's parts not stated, its target not the asset or a system it names, a
    # mechanism naming nothing of this asset, a generic line, a weakness stated as fact on nothing recorded;
    # a system the attack involves left unnamed (a warning).
    ANATOMY_MISSING = "anatomy_missing"
    TARGET_NOT_NAMED = "target_not_named"
    MECHANISM_NOT_CONCRETE = "mechanism_not_concrete"
    VAGUE_PHRASE = "vague_phrase"
    UNSUPPORTED_WEAKNESS = "unsupported_weakness"
    APPLICABLE_SYSTEM_NOT_IN_STORY = "applicable_system_not_in_story"
    NEAR_DUPLICATE = "near_duplicate"  # G229: it reads almost like a scenario of the run already finished
    # G232: a sentence says something happened in the deployment's country, citing no source that tells of it
    COUNTRY_CLAIM_UNSUPPORTED = "country_claim_unsupported"


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
    FindingCode.SYSTEM_LINK_CLAIMED: FindingSeverity.BLOCKER,  # G229: an unsupported relationship rejects
    FindingCode.PLAN_CHECK: FindingSeverity.NOTE,
    FindingCode.PLAN_CHECK_NOT_MADE: FindingSeverity.NOTE,
    FindingCode.STATEMENT_LENGTH: FindingSeverity.WARNING,  # rewritten once, never blocked
    FindingCode.RISK_LENGTH: FindingSeverity.WARNING,
    # G250 (owner 2026-10-15): a story citing nothing is kept, its closest source shown, never numbered.
    FindingCode.NO_EVIDENCE_CITED: FindingSeverity.WARNING,
    FindingCode.CITATION_REMOVED: FindingSeverity.WARNING,  # G252: shown to the reviewer, never blocking
    FindingCode.EVIDENCE_LINK_MISSING: FindingSeverity.BLOCKER,
    FindingCode.CITATION_UNSUPPORTED: FindingSeverity.BLOCKER,
    FindingCode.ANATOMY_MISSING: FindingSeverity.BLOCKER,
    FindingCode.TARGET_NOT_NAMED: FindingSeverity.BLOCKER,
    FindingCode.MECHANISM_NOT_CONCRETE: FindingSeverity.BLOCKER,
    FindingCode.VAGUE_PHRASE: FindingSeverity.BLOCKER,
    FindingCode.UNSUPPORTED_WEAKNESS: FindingSeverity.BLOCKER,
    FindingCode.APPLICABLE_SYSTEM_NOT_IN_STORY: FindingSeverity.WARNING,
    FindingCode.NEAR_DUPLICATE: FindingSeverity.BLOCKER,
    FindingCode.COUNTRY_CLAIM_UNSUPPORTED: FindingSeverity.BLOCKER,
}

#: G229 (owner 2026-10-13: "Do not retry an AI request when validation fails. Reject the invalid candidate and
#: follow the bounded replacement policy"): a scenario blocked by one of these is final, its path given up at
#: once and never written again.
FINAL_FINDINGS: Final[frozenset[FindingCode]] = frozenset({
    FindingCode.EVIDENCE_LINK_MISSING, FindingCode.CITATION_UNSUPPORTED,
    FindingCode.ANATOMY_MISSING, FindingCode.TARGET_NOT_NAMED, FindingCode.MECHANISM_NOT_CONCRETE,
    FindingCode.VAGUE_PHRASE, FindingCode.UNSUPPORTED_WEAKNESS, FindingCode.SYSTEM_LINK_CLAIMED,
    FindingCode.NEAR_DUPLICATE, FindingCode.COUNTRY_CLAIM_UNSUPPORTED,
})  # fmt: skip

#: The G229 findings never ask for the one rewrite (no AI call is added for them): each is listed in it only
#: when the rewrite runs anyway, for a finding it always ran for (the claimed link among them).
#: G250: a story citing nothing never asks for one either (its closest source is shown instead: no AI call).
NO_REWRITE_FINDINGS: Final[frozenset[FindingCode]] = (FINAL_FINDINGS - {FindingCode.SYSTEM_LINK_CLAIMED}) | {
    FindingCode.APPLICABLE_SYSTEM_NOT_IN_STORY,
    FindingCode.NO_EVIDENCE_CITED,
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
    TEXT_LENGTH = "The {text} has {words} words; write {least} to {most}."
    NO_EVIDENCE_CITED = (
        "Cites none of the {count} evidence entries (cite one that directly supports a claim): the closest "
        "related source is shown, not cited by any sentence."
    )
    EVIDENCE_LINK_MISSING = "Gives no supported claim (evidence_links) for the marker(s) {markers}."
    CITATION_REMOVED = (
        "Removed the citation(s) {markers}: their sources do not support the claim beside them (a sentence "
        "claiming a past event with them was taken out; on an attack step only the marker)."
    )
    ANATOMY_MISSING = (
        "Does not state its parts ({parts}): a finished scenario gives its target, entry point, mechanism "
        "and consequence."
    )
    TARGET_NOT_NAMED = "Its target ({target}) is not the asset or one of its systems named in the scenario."
    MECHANISM_NOT_CONCRETE = "Its attack mechanism names no component, system or technology of this asset."
    VAGUE_PHRASE = "Uses a generic line ({phrases}) where the concrete action belongs."
    UNSUPPORTED_WEAKNESS = "States a weakness as fact ({claims}) that nothing recorded or cited supports."
    APPLICABLE_SYSTEM_NOT_IN_STORY = "Does not name {systems}, which this attack involves."
    NEAR_DUPLICATE = "Reads almost like scenario {scenario_id} of this run ({similarity}% of its wording)."
    CITATION_UNSUPPORTED = "The marker(s) {markers} sit by claims their evidence entries do not support."
    COUNTRY_CLAIM_UNSUPPORTED = (
        "Says something happened in the {country} at marker(s) {markers}, but none of those sources tells of "
        "the {country}: regional or global intelligence is never a {country} incident."
    )


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
