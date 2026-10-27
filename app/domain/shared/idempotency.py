"""A repeat of an Idempotency-Key the server derived (the caller sent none) is refused, never replayed."""

from datetime import datetime

from app.core.clock import utc_now
from app.core.constants import ConflictReason, ErrorMessage, Idempotency
from app.core.exceptions import Conflict


def is_derived_key(key: str) -> bool:
    """Whether the server derived this key because the request had no Idempotency-Key."""
    return key.startswith(Idempotency.DERIVED_PREFIX)


def duplicate_request(started_at: datetime, **first: str | int) -> Conflict:
    """409 duplicate_request naming what the first request started (`first`) and how many seconds ago."""
    seconds = max(0, round((utc_now() - started_at).total_seconds()))
    named = ", ".join(f"{name} {value}" for name, value in first.items())
    window = Idempotency.DERIVED_WINDOW_SECONDS
    message = ErrorMessage.DUPLICATE_REQUEST.format(seconds=seconds, first=named, window=window)
    details = {**first, "started_seconds_ago": seconds}
    return Conflict(message, reason=ConflictReason.DUPLICATE_REQUEST, details=details)
