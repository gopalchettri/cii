"""What every intelligence source class offers the refresh: one method, so a new source is one new class."""

from typing import Protocol

from app.core.constants import IntelSource
from app.models.external_intelligence.fetch_result import FetchResult


class IntelSourceFetcher(Protocol):
    source_id: IntelSource

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The source's records since `checkpoint` (None: the first run, everything); None when the source
        has nothing new. Raises IntelFetchFailed when it cannot be read."""
        ...
