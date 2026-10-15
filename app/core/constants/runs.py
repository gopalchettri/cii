"""Runs and their scenarios: generation limits, messages, run actions and conflicts."""

from enum import StrEnum
from typing import Final


class Generation:
    # Paths written at once by one write job, which then hands the set's next ones to itself: a concurrency
    # bound, never a limit on the number of scenarios (the set sizes are INITIAL_SET_SIZE / NEXT_SET_SIZE).
    WRITER_BATCH: Final = 6
    MAX_PATH_ATTEMPTS: Final = 5  # failed or blocked this often, a path is abandoned and never served
    MAX_SUPPORTING_SYSTEMS: Final = 0  # 0 = unlimited, any number fixed = limit to that number of supporting systems. eg: 50  # noqa: E501


class SessionMessage(StrEnum):
    NOT_FOUND = "Session '{session_id}' does not exist."
    OTHER_ENTITY = "Session '{session_id}' belongs to another entity."
    ASSET_NOT_OWNED = "Asset {asset_id} does not belong to your entity."
    SYSTEMS_NOT_LINKED = "Supporting systems {system_ids} are not linked to asset {asset_id}."
    SERVICE_NOT_FOUND = "Service {service_id} does not exist."
    SECTOR_NOT_FOUND = "Sector {sector_id} does not exist."
    SECTOR_NOT_PARENT = (
        "Sector {sector_id} is not the parent of sub-sector {subsector_id}; its sector is {parent_id}."
    )
    ACTIVE_SESSION_EXISTS = "Asset {asset_id} already has an active run."
    IDEMPOTENCY_KEY_CONFLICT = "This Idempotency-Key was already used for another request."
    ENTITY_MISMATCH = "The entity in the path is not the caller's entity."
    ENTITY_MISMATCH_BODY = "manual_scenario.entity_id is not the caller's entity (X-Entity-Id)."
    SCENARIO_NOT_FOUND = "Scenario '{scenario_id}' does not exist in session '{session_id}'."
    SYSTEMS_REQUIRED = "Send at least one supporting system."
    SYSTEMS_REPEATED = "Each supporting system may be sent only once."
    TOO_MANY_SYSTEMS = "A run takes at most {limit} supporting systems."


class GroundingStatus(StrEnum):
    """A scenario's threat.grounding_status in the results (v1's words)."""

    VERIFIED = "verified"  # a library threat
    AI_PROPOSED = "ai_proposed"  # proposed by the AI for a category the library did not cover (gap-fill)
    PERSON_PROPOSED = "person_proposed"  # named by the person who wrote the scenario; proposed to the library


class ValidationStatus(StrEnum):
    """Scenario.validation.status, computed on read."""

    OK = "ok"
    WARNING = "warning"


class ScenarioDisplay:
    #: Scenario.display_statement = the statement, this, then why_applies (two line breaks between).
    WHY_APPLIES_JOIN: Final = "\n\nWhy this threat applies: "


class RunKind(StrEnum):
    GENERATED = "generated"  # threats, paths and scenarios made by the engine
    MANUAL = "manual"  # one hand-written scenario (remediation request, Step 16): born done


class RunActionKind(StrEnum):
    """last_action.kind: what the reviewer last asked of the run."""

    START = "start"
    NEXT_SET = "next_set"
    REGENERATE = "regenerate"


class RunActionOutcome(StrEnum):
    RUNNING = "running"
    COMPLETE = "complete"
    # Done, but not all the work could be done: a category the AI could not judge, or a path that failed or
    # was abandoned. Never shown as complete (G113, spec v4.0 §7.3.7).
    PARTIAL = "partial"
    # The job failed (its error is job.error): set wherever a job is failed, so a failed run never still reads
    # "running" (G141).
    FAILED = "failed"
    CANCELLED = "cancelled"  # stopped by its owner (G214)


class StageState(StrEnum):
    """One stage of a run (threats, scenarios, controls) as the status shows it (owner 2026-10-12)."""

    PENDING = "PENDING"  # not started yet
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"  # stopped by its owner (G214)


class RunOverall(StrEnum):
    """What the reviewer should do now (the status's progress.overall)."""

    PENDING = "pending"  # nothing started yet
    IN_PROGRESS = "in_progress"  # wait: work is going on
    AWAITING_REVIEW = "awaiting_review"  # scenarios wait for an accept or a reject
    AWAITING_NEXT_SET = "awaiting_next_set"  # all written ones decided; paths remain: ask for the next set
    COMPLETE = "complete"  # everything written and decided
    ERROR = "error"  # the run failed: progress.error_message says why
    CANCELLED = "cancelled"  # its owner stopped it: what was done stays readable (G214)


class SessionState(StrEnum):
    """The run as a whole (the status's session_status)."""

    ACTIVE = "active"  # a job is queued or running
    COMPLETED = "completed"  # the work asked for is done
    FAILED = "failed"
    CANCELLED = "cancelled"  # its owner stopped it (G214)


class BoardMessage(StrEnum):
    """progress.error_message texts the status writes itself (a failed job brings its own message)."""

    ABANDONED = "{abandoned} attack path(s) could not be written; the results give each one's reason."
    NOT_ASSESSED = (
        "These threat categories could not be fully assessed, so the threats found are partial: {categories}."
    )
    CONTROLS_FAILED = (
        "Controls could not be matched for {failed} scenario(s) yet; they are tried again later."
    )
    # A hand-written run's: nothing retries it in the background; its plan job maps it, and a regenerate of
    # its plan tries again (G262).
    CONTROLS_FAILED_MANUAL = (
        "Controls could not be matched for the hand-written scenario; regenerate its plan "
        "(POST .../treatment-plan/regenerate) to try again."
    )
    CANCELLED = "Cancelled by user {user} at {at} UTC."
    CONTROLS_CANCELLED = "Matching controls was cancelled for {cancelled} scenario(s)."


class RunClash(StrEnum):
    """Why a run could not be inserted or queued again (tsg_sessions): a unique index, or a newer change."""

    ACTIVE_RUN = "active_run"  # one active run per asset
    IDEMPOTENCY_KEY = "idempotency_key"  # one run per Idempotency-Key per entity
    CHANGED = (
        "changed"  # the run moved on since it was read (another click, a worker): its job was not replaced
    )
    DELETING = "deleting"  # its owner is deleting it (or just did): nothing more starts on it (G214)


class ConflictReason(StrEnum):
    """The `reason` of a 409 (one enum for runs, scenarios and remediation); the API never changes one."""

    ACTIVE_SESSION_EXISTS = "active_session_exists"
    IDEMPOTENCY_KEY_CONFLICT = "idempotency_key_conflict"
    GENERATION_IN_PROGRESS = "generation_in_progress"
    RUN_FAILED = "run_failed"
    RUN_CANCELLED = "run_cancelled"  # cancelled before its plan: nothing to decide or resume (G214)
    # Review (Step 14): each refusal names its rule; per-id reasons are TargetProblem (constants/review.py).
    SCENARIOS_NOT_DECIDABLE = "scenarios_not_decidable"
    SCENARIOS_NOT_REGENERABLE = "scenarios_not_regenerable"
    NOTHING_TO_ACCEPT = "nothing_to_accept"
    DUPLICATE_VERSION = "duplicate_version"
    NOTHING_LEFT = "nothing_left"
    TARGET_REACHED = "target_reached"
    SCENARIOS_ABANDONED = "scenarios_abandoned"
    ASSET_BUSY = "asset_busy"
    SCENARIO_NOT_ACCEPTED = "scenario_not_accepted"
    NOTHING_TO_PROMOTE = "nothing_to_promote"
    TYPE_MISMATCH = "type_mismatch"  # a 422 reason: the threat the library holds is of another type
    VERSION_NOT_FOUND = "version_not_found"  # a 404 reason: the plan has no such version
    NOT_COMPLETE = "not_complete"  # a plan version still being written, or failed, cannot be decided
    CHANGED_CONCURRENTLY = "changed_concurrently"  # another decision landed twice while this one was made
    PLAN_ALREADY_EXISTS = "plan_already_exists"  # one plan per scenario: regenerate it instead
    ASSET_NOT_OWNED = "asset_not_owned"  # a 403 reason
    SYSTEM_NOT_LINKED = "system_not_linked"  # a 403 reason
    # A 422 reason: a property the owner requires (ASSET_/SYSTEM_PROPERTIES_REQUIRED) is not recorded.
    REQUIRED_FACTS_MISSING = "required_facts_missing"
    JOB_IN_PROGRESS = "job_in_progress"  # an admin job of this kind is queued or running (#18)
    NOTHING_TO_CANCEL = "nothing_to_cancel"  # no job of it is queued or running (G214)
    CANCEL_FIRST = "cancel_first"  # a delete refused while a job of it is queued or running (G214)
    RUN_BEING_DELETED = "run_being_deleted"  # a next set or regenerate refused: the run is being deleted
    INTEL_NO_DATA = "intel_no_data"  # a run refused: external intelligence is on but nothing is imported yet


class CoverageGap(StrEnum):
    """Why a supporting system or a kind of attack has no selected scenario (the plan's coverage, G223)."""

    NO_RELEVANT_THREAT = "no_relevant_threat"  # no threat was judged relevant to it: none is forced on it
    LIMIT_REACHED = "scenario_limit_reached"  # it had paths, but TOTAL_SCENARIO_COUNT kept others
    SCENARIOS_FAILED = "scenarios_failed"  # its selected paths all failed for good (abandoned, G227)
    AWAITING_NEXT_SET = "awaiting_next_set"  # its selected paths are not written yet: a next set writes them


class UnselectedReason(StrEnum):
    """Why a valid attack path gets no scenario (stored on the path in the plan)."""

    TARGET_REACHED = "target_reached"  # TOTAL_SCENARIO_COUNT kept more relevant paths
    # G229: it failed for good and a reserve path (one TOTAL_SCENARIO_COUNT had left out) took its place.
    REPLACED_AFTER_FAILURE = "replaced_after_failure"
