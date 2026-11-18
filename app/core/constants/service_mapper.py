"""The service mapper's stored values: its 409 reasons, decision failures and progress."""

from enum import StrEnum


class MapperConflict(StrEnum):
    GENERATION_IN_PROGRESS = "generation_in_progress"
    GENERATION_LIMIT_REACHED = "generation_limit_reached"


class MapperDecisionFailure(StrEnum):
    """Why one id of a relationship decision was not saved (the others still are)."""

    DEPENDENCY_NOT_FOUND = "dependency_not_found"


class MappingOverall(StrEnum):
    """Where a mapping's generation is (progress.overall)."""

    FAILED = "failed"  # the generation failed: `error` says why
    CANCELLED = "cancelled"
    GENERATING = "generating"  # queued or running: wait
    DONE = "done"  # its relationships can be decided (progress.relationships counts them)
