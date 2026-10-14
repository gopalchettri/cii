"""Stores what a source delivered in batches of IntelLimits.BATCH_SIZE, then retires what it dropped.

Every write is fenced: before each batch (and before the retirement) the caller says whether it still holds
the source's claim, and a worker that lost it stops with ClaimLost instead of writing older versions over a
newer owner's. A complete result that holds under IntelOperationsLimits.MIN_RETIRE_RATIO of the source's
current records is refused before anything is written (WriteRefused): a cut-short feed is a failed fetch."""

from collections.abc import Callable
from datetime import datetime

from app.core.constants import IntelLimits, IntelMessage, IntelOperationsLimits, IntelSource
from app.core.exceptions import IntelFetchFailed
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import SaveCounts
from app.services.external_intelligence.refresh_messages import RefreshMessage


class ClaimLost(Exception):  # noqa: N818 - an outcome the refresher answers, not an error report
    """The claim on the source was taken over or the source was revoked: nothing more may be written."""


class WriteRefused(Exception):  # noqa: N818 - like IntelFetchFailed: carries a people-readable text
    """The result is not stored; `message` (a RefreshMessage, filled in) says why."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class RecordBatchWriter:
    def __init__(self, record_store: IntelRecordStore) -> None:
        self._records = record_store

    def write_result(
        self, source: IntelSource, result: FetchResult, now: datetime, still_ours: Callable[[], bool]
    ) -> tuple[SaveCounts, int]:
        """The counts stored and how many records were retired. A source that returns nothing (and is not
        a partial pass) is a failure, never a reason to retire what it had; so is a complete result that
        lacks most of what the source had (WriteRefused, nothing stored). A partial pass retires nothing:
        a record it left out is not gone. Raises ClaimLost when `still_ours()` turns False."""
        if not result.records and not result.partial:
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=source)
        seen = {record.external_id for record in result.records}
        if not result.partial:
            self._refuse_a_cut_short_feed(source, seen)
        size = IntelLimits.BATCH_SIZE
        total = SaveCounts(0, 0, 0)
        for start in range(0, max(len(result.records), 1), size):
            if not still_ours():
                raise ClaimLost
            rejected = result.rejected if start == 0 else ()
            total += self._records.save_batch(result.records[start : start + size], rejected, now)
        if result.partial:
            return total, 0
        if not still_ours():
            raise ClaimLost
        return total, self._records.retire_records_missing_from(source, seen, now)

    def _refuse_a_cut_short_feed(self, source: IntelSource, seen: set[str]) -> None:
        current = self._records.list_current_external_ids(source)
        kept = len(current & seen)
        if current and kept < IntelOperationsLimits.MIN_RETIRE_RATIO * len(current):
            raise WriteRefused(
                RefreshMessage.CUT_SHORT.format(source=source, kept=kept, current=len(current))
            )
