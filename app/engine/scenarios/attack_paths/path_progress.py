"""A frozen plan's attack paths: which are still open, the next set a person asked for, the next ones to
write, the plan's figures, and why none is left. One rule for the plan job, the write job
(app/worker/plan_progress.py) and the next-set call. Pure functions on the plan's path records."""

from collections.abc import Iterable
from typing import Any

from app.core.constants import ConflictReason, Generation, UnselectedReason


def is_still_to_write(path: dict[str, Any]) -> bool:
    """Not written yet and not set aside after Generation.MAX_PATH_ATTEMPTS."""
    return not path["served"] and not path["abandoned"]


def next_set_paths(paths: Iterable[dict[str, Any]], size: int) -> list[str]:
    """The ids of the next `size` selected, still-open paths, best rank first: the first set
    (INITIAL_SET_SIZE) or the next one (NEXT_SET_SIZE; owner 2026-10-11, as v1). A path an interruption left
    unwritten ranks before the paths never asked for, so it is written within the set, never on top of it."""
    left = sorted(
        (path for path in paths if path["selected"] and is_still_to_write(path)),
        key=lambda path: path["rank"],
    )
    return [path["path_id"] for path in left[:size]]


def set_and_first_batch(paths: Iterable[dict[str, Any]], size: int) -> tuple[list[str], list[dict[str, Any]]]:
    """The next set of `size` paths (next_set_paths) and its first batch to write: what the plan job hands the
    write job (INITIAL_SET_SIZE) and what a next-set call queues (NEXT_SET_SIZE), one rule for both."""
    paths = list(paths)
    asked = next_set_paths(paths, size)
    return asked, next_paths_to_write(path for path in paths if path["path_id"] in asked)


def next_paths_to_write(paths: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The next paths to write: selected and still open, never-tried ones first, best rank first; at most
    Generation.WRITER_BATCH at once (the threads a write delivery uses)."""
    left = sorted(
        (path for path in paths if path["selected"] and is_still_to_write(path)),
        key=lambda path: (path["attempts"] > 0, path["rank"]),
    )
    return [{"path_id": path["path_id"], "replaces": None} for path in left[: Generation.WRITER_BATCH]]


def plan_counts(paths: Iterable[dict[str, Any]]) -> dict[str, int]:
    paths = list(paths)
    selected = [path for path in paths if path["selected"]]
    replaced = UnselectedReason.REPLACED_AFTER_FAILURE  # G229: given up, a reserve took its place
    return {
        "planned": len(selected),
        "remaining": sum(is_still_to_write(path) for path in selected),
        "abandoned": sum(bool(path["abandoned"]) for path in selected),
        "replaced": sum(path.get("unselected_reason") == replaced for path in paths),
    }


def why_no_path_left(paths: Iterable[dict[str, Any]]) -> ConflictReason:
    """Why next_set_paths found nothing: selected paths set aside after repeated failures, paths the scenario
    count (TOTAL_SCENARIO_COUNT) left out, or simply every path written."""
    paths = list(paths)
    if any(path["selected"] and path["abandoned"] for path in paths):
        return ConflictReason.SCENARIOS_ABANDONED
    if any(not path["selected"] for path in paths):
        return ConflictReason.TARGET_REACHED
    return ConflictReason.NOTHING_LEFT
