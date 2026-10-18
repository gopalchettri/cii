"""When a source is due a refresh, which stored checkpoint is trusted, when a claim is stale, and which
delivered feeds are refused before anything is written."""

from datetime import datetime, timedelta

from app.core.constants import REFRESH_AFTER_HOURS, IntelLimits, IntelOperationsLimits, IntelSource


def is_refresh_due(
    source: IntelSource, last_success_at: datetime | None, more_pending: bool, now: datetime
) -> bool:
    """True when the source never succeeded, its last run was cut short, or its period has passed."""
    if last_success_at is None or more_pending:
        return True
    return now - last_success_at >= timedelta(hours=REFRESH_AFTER_HOURS[source])


def claim_stale_before(now: datetime) -> datetime:
    """A refresh claimed before this moment belongs to a dead worker and may be taken over."""
    return now - timedelta(seconds=IntelLimits.CLAIM_STALE_SECONDS)


def trusted_checkpoint(checkpoint: str | None, source_version: str | None) -> str | None:
    """The stored checkpoint, trusted only with its version (they are saved together): a row missing either
    is downloaded in full."""
    return checkpoint if source_version is not None else None


def is_empty_complete_feed(record_count: int, partial: bool) -> bool:
    """True for a complete result with no records: the source failed, nothing is retired."""
    return not record_count and not partial


def is_cut_short_feed(current_count: int, kept: int) -> bool:
    """True when a complete result keeps under MIN_RETIRE_RATIO of the source's current records."""
    return bool(current_count) and kept < IntelOperationsLimits.MIN_RETIRE_RATIO * current_count
