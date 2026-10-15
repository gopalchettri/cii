"""Service Mapper: directions, confidence, review actions and statuses, the live-status event, error texts
and the fixed ids the stub answers with (its error ids let a UI developer see every error response)."""

from enum import StrEnum
from typing import Final


class MapperDirection(StrEnum):
    """From the selected service's point of view: upstream = it needs this service, downstream = this service
    relies on it."""

    UPSTREAM = "upstream"
    DOWNSTREAM = "downstream"


class MapperConfidence(StrEnum):
    """The model's own estimate, not a probability."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MapperAction(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class MapperRecommendationStatus(StrEnum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"  # was proposed when a newer round started


class MapperEvent(StrEnum):
    STATUS = "status"  # the one live-status event: ids and status only, never the result


class MapperConflict(StrEnum):
    """The `reason` of a 409."""

    GENERATION_IN_PROGRESS = "generation_in_progress"
    DECISION_FINAL = "decision_final"
    SUPERSEDED = "superseded"


class MapperMessage(StrEnum):
    NOT_YOUR_ENTITY = "entity_id must be the caller's entity (the X-Entity-Id header)."
    MAPPING_NOT_FOUND = "No such mapping."
    ROUND_RUNNING = "A round is already running for this mapping."
    DECISION_FINAL = "This recommendation was already decided differently; decisions are final."
    RECOMMENDATION_SUPERSEDED = "A newer round replaced this recommendation."
    ONE_SERVICE_ONLY = "Give service_id (an existing service) or service_name (a new one): exactly one."


class MapperLimits:
    MAX_SERVICE_NAME_CHARS: Final = 255
    MAX_COMMENT_CHARS: Final = 2_000


class MapperSample:
    """Fixed answers of the stub. The all-zero ids end in a digit that picks the error a caller sees."""

    MAPPING_ID: Final = "6a1f0c2e9b7d4e58a3c1d2e4f5a60718"
    ACCEPTED_ID: Final = "c41d9e07b2a84f6e9d5a3b1c7e8f2a60"
    REJECTED_ID: Final = "e5b2a7c9013d4f68b9a1c3d5e7f90214"
    PROPOSED_ID: Final = "0b7e3d5a9c1f4286a4d6e8f0b2c41973"
    UNKNOWN_MAPPING_ID: Final = "0" * 32  # any call on it: 404
    BUSY_MAPPING_ID: Final = "0" * 31 + "1"  # regenerate on it: 409 generation_in_progress
    DECIDED_RECOMMENDATION_ID: Final = "0" * 31 + "2"  # decide on it: 409 decision_final
    STALE_RECOMMENDATION_ID: Final = "0" * 31 + "3"  # decide on it: 409 superseded
    SERVICE_ID: Final = 31
    SERVICE_NAME: Final = "Online Payment Service"
    SECTOR: Final = "Finance"
    SUB_SECTOR: Final = "Payments"
