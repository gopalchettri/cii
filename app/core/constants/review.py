"""Reviewing scenarios (Step 14, BUILD_PLAN S37-S42): accept, reject, regenerate, next set, and an accepted
AI-proposed threat promoted to the library."""

from enum import StrEnum
from typing import Final


class Review:
    MAX_IDS_PER_CALL: Final = 50  # scenario ids per accept, reject or regenerate call (BR-SCN-02)
    MAX_ID_CHARS: Final = 64  # a scenario id is a 36-character uuid: a longer one is refused (422)


class TargetProblem(StrEnum):
    """Why one scenario id of a review call is refused (`errors[].reason`) or left out
    (`skipped[].reason`)."""

    UNKNOWN = "unknown"  # not a served scenario of this run
    FAILURE_SCENARIO = "failure_scenario"  # a failure card: the write job retries its path
    ALREADY_REJECTED = "already_rejected"  # decisions are final (S37); regenerate to get a new version
    ALREADY_ACCEPTED = "already_accepted"
    DUPLICATE_VERSION = "duplicate_version"  # two versions of one path, or another version already accepted
    LIBRARY_INACTIVE = "library_inactive"  # its library threat was retired after it was written
    VERSION_NOT_CURRENT = "version_not_current"  # a newer version replaced it: regenerate the newest one
    CHANGED_CONCURRENTLY = "changed_concurrently"  # another call decided it between this call's read, write
    HAND_WRITTEN = (
        "hand_written"  # a person wrote it (Step 16): the writer has no plan path to write it again
    )


class PromotionOutcome(StrEnum):
    """What promoting one AI-proposed threat did (#27)."""

    INSERTED = "inserted"  # written to the library as pending: a curator approves or rejects it (#24)
    EXISTING = "existing"  # the library already has it, live or pending: nothing written
    CURATOR_REJECTED = "curator_rejected"  # a curator rejected this wording: never proposed again (FR-LIB-05)


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
    SCENARIOS_ABANDONED = (
        "The attack paths of run '{session_id}' still unwritten were set aside after repeated failures."
    )
    ASSET_BUSY = "Asset {asset_id} has another active run: try again once it is done."
    SCENARIO_NOT_ACCEPTED = "Scenario '{scenario_id}' is not accepted: accept it before promoting its threat."
    NOTHING_TO_PROMOTE = "Scenario '{scenario_id}' is built on a library threat: there is nothing to promote."
