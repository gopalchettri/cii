"""The service mapper's values: its 409 reasons, decision failures, progress, messages and limits."""

from enum import StrEnum
from typing import Final


class MapperConflict(StrEnum):
    """The `reason` of a service mapper 409."""

    GENERATION_IN_PROGRESS = "generation_in_progress"


class MapperDecisionFailure(StrEnum):
    """Why one id of a relationship decision was not saved (the others still are)."""

    DEPENDENCY_NOT_FOUND = "dependency_not_found"
    DECISION_FINAL = "decision_final"


class MappingOverall(StrEnum):
    """Where a mapping's generation is (progress.overall)."""

    FAILED = "failed"  # the generation failed: `error` says why
    CANCELLED = "cancelled"
    GENERATING = "generating"  # queued or running: wait
    DONE = "done"  # its relationships can be decided (progress.relationships counts them)


class MapperMessage(StrEnum):
    AI_ANSWER_INVALID = "The AI answer did not satisfy the Service Mapper output contract."
    AI_ANSWER_TOO_LONG = (
        "The AI answer was too long for the model; lower SERVICE_MAPPER_UPSTREAM_TOTAL_COUNT or "
        "SERVICE_MAPPER_DOWNSTREAM_TOTAL_COUNT."
    )
    IDEMPOTENCY_KEY_CONFLICT = "This Idempotency-Key was already used for another mapping input."
    MAPPING_NOT_READY = "The mapping is not done: wait while it generates, or regenerate it if it failed."
    DEPENDENCY_NOT_FOUND = "No such dependency in the current generation."
    NOTHING_TO_DECIDE = "Name at least one dependency_id in accept or reject."
    ACCEPTED_AND_REJECTED = "A dependency_id cannot be both accepted and rejected: {ids}."
    TOO_MANY_DECISIONS = "At most {limit} dependency ids per request."
    REQUIRED_VALUE_BLANK = "A required value cannot be blank."
    ENTITY_NAME_INVALID = "Each entity name must contain 1 to 255 characters."
    ENTITY_NAMES_REPEATED = "Entity names must be unique."
    CATALOG_RESULT_SETS = "The Service Mapper SQL procedures returned an unexpected number of result sets."
    CATALOG_ROW_INVALID = "The Service Mapper SQL catalog contains an invalid or inconsistent row."
    NOT_YOUR_ENTITY = "entity_id must be the caller's entity (the X-Entity-Id header)."
    MAPPING_NOT_FOUND = "No such mapping."
    ROUND_RUNNING = "A round is already running for this mapping."
    DECISION_FINAL = "This recommendation was already decided differently; decisions are final."


class MapperLimits:
    CANDIDATE_POOL: Final = 80
    MAX_DECISIONS: Final = 200  # ids per relationship decision: both directions at their largest count (100)
    PROMPT_SHARE: Final = 0.55  # the most of the model's input the prompt fills before the catalog is cut
    PROMPT_RESERVE_CHARS: Final = 4_000  # input kept free for the re-ask turn
    SELECTED_RECORD_CHARS: Final = 1_000  # the selected service's recorded upstream / downstream text
    CATALOG_DESCRIPTION_CHARS: Final = 240  # each catalog service's description
    # Each catalog service's recorded upstream / downstream text. Longer shows fewer services in the prompt
    # budget: DESC with records fits all 68 at 240 (~54k chars) and at 600 (~100k) under dev's 263,136-char
    # limit (UAT's is larger); it was 36 and 18 under the old shared 60,000 (2026-10-23).
    CATALOG_RECORD_CHARS: Final = 240
    REASK_NAMES_SHOWN: Final = 8  # catalog services named in one re-ask problem
    SCHEMA_ERRORS_SHOWN: Final = 10  # answer-format errors sent back in a re-ask
    HISTORY_KEEP_DAYS: Final = 90  # an archived generation is deleted this long after it was archived
