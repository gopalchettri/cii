"""Stores what a source delivered in fenced batches, then retires what it dropped; a cut-short complete feed
is refused before anything is written."""

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum

from app.core.constants import IntelLimits, IntelMessage, IntelOperationsLimits, IntelSource
from app.core.exceptions import IntelFetchFailed
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import SaveCounts


class RefreshMessage(StrEnum):
    """The words a failed source refresh is recorded in (the sources' own failures use IntelMessage)."""

    UNEXPECTED = "The refresh stopped with an unexpected {error}."
    REVOKED = "{source} was revoked during the refresh: nothing was stored."
    CUT_SHORT = (
        "{source} delivered only {kept} of its {current} current records: the feed looks cut short, so "
        "nothing was stored or retired and the last good data stays."
    )


class ClaimLost(Exception):
    """The claim on the source was taken over or the source was revoked: nothing more may be written."""


class WriteRefused(Exception):
    """The result is not stored; `message` (a RefreshMessage, filled in) says why."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def write_fetch_result(
    records: IntelRecordStore,
    source: IntelSource,
    result: FetchResult,
    now: datetime,
    still_ours: Callable[[], bool],
) -> tuple[SaveCounts, int]:
    """Store `result` in batches of IntelLimits.BATCH_SIZE and retire what a complete result left out; return
    the counts stored and how many records were retired. An empty complete result fails the source; a partial
    one retires nothing. Raises ClaimLost when `still_ours()`, asked before every write, turns False."""
    if not result.records and not result.partial:
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=source)
    seen = {record.external_id for record in result.records}
    if not result.partial:
        _refuse_a_cut_short_feed(records, source, seen)
    size = IntelLimits.BATCH_SIZE
    total = SaveCounts(0, 0, 0)
    for start in range(0, max(len(result.records), 1), size):
        if not still_ours():
            raise ClaimLost
        rejected = result.rejected if start == 0 else ()
        total += records.save_batch(result.records[start : start + size], rejected, now)
    if result.partial:
        return total, 0
    if not still_ours():
        raise ClaimLost
    return total, records.retire_records_missing_from(source, seen, now)


def _refuse_a_cut_short_feed(records: IntelRecordStore, source: IntelSource, seen: set[str]) -> None:
    """Raise WriteRefused when a complete result holds under MIN_RETIRE_RATIO of the current records."""
    current = records.list_current_external_ids(source)
    kept = len(current & seen)
    if current and kept < IntelOperationsLimits.MIN_RETIRE_RATIO * len(current):
        raise WriteRefused(RefreshMessage.CUT_SHORT.format(source=source, kept=kept, current=len(current)))
