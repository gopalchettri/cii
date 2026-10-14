"""NIST NVD API 2.0: one VULNERABILITY_DETAIL record per CVE we care about (the KEV CVEs), joined to the KEV
vulnerability by CVE id. Records are never retired here: a run holds only the CVEs it reached (`partial`).

A run is bounded (IntelLimits.NVD_MAX_REQUESTS_PER_RUN) and paced under NVD's limit (nvd_api_client.py). Two
phases; the first pass is resumable across runs without any cursor:
1. CHANGED: when the checkpoint is a time, one lastModStartDate/lastModEndDate window since it (at most
   NVD_MAX_WINDOW_DAYS), keeping only the wanted CVEs. One call per 2,000 changed CVEs of all NVD, not one per
   CVE. The window is done, and the checkpoint moves to its end, only when every page was read.
2. MISSING: `cveId=` lookups, in sorted order, for the wanted CVEs not yet stored (this is the first pass and
   every CVE KEV gains later). Each run's records are committed before the next run starts, so "not yet
   stored" (`stored_cves`) is the resume point; a CVE KEV adds in the middle of a pass is one more missing.
Checkpoint: the ISO-8601 UTC time (`2026-10-12T01:39:00.000+00:00`) up to which every stored CVE is known to
be current. Run one sets it to the time that run started; a later run advances it to the end of the window it
finished. `more` is true only when the budget or a rate limit cut the run short."""

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from app.core.config import get_settings
from app.core.constants import IntelLimits, IntelSource
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord
from app.services.external_intelligence.sources.nvd_api_client import NvdApiClient
from app.services.external_intelligence.sources.nvd_item_reader import NvdItemReader
from app.services.external_intelligence.sources.text_guard import SourceTextGuard, limit_rejected

_TIME = "%Y-%m-%dT%H:%M:%S.000+00:00"


class _Collected:
    """The records and rejections one run gathered, by CVE id (local to one call)."""

    def __init__(self) -> None:
        self.records: dict[str, IntelRecord] = {}
        self.rejected: list[RejectedRecord] = []


class NistNvdDetailsSource:
    source_id = IntelSource.NIST_NVD

    def __init__(
        self,
        known_cves: Callable[[], set[str]],
        stored_cves: Callable[[], set[str]],
        *,
        api_key: Callable[[], str] | None = None,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._known_cves = known_cves
        self._stored_cves = stored_cves
        self._api_key = api_key or (lambda: get_settings().nvd_api_key.get_secret_value())
        self._client = client
        self._sleep = sleep
        self._clock = clock or (lambda: datetime.now(UTC))
        self._reader = NvdItemReader(SourceTextGuard(IntelSource.NIST_NVD))

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The records this run reached (always `partial`), or None when there is nothing to ask for."""
        wanted = {cve.upper() for cve in self._known_cves()}
        if not wanted:
            return None
        started, since = self._clock(), _parse_time(checkpoint)
        found, cut = _Collected(), False  # cut: the budget or a rate limit ended the run early
        api = NvdApiClient(self._api_key(), self._client, self._sleep)
        try:
            moved_to = started if since is None else self._read_changed(api, since, started, wanted, found)
            if moved_to is None:
                cut = True
            for cve in sorted(wanted - self._stored_cves() - found.records.keys()):
                body = api.get({"cveId": cve})
                if body is None:
                    cut = True
                    break
                self._collect(body["vulnerabilities"], wanted, found)
        finally:
            api.close()
        new_checkpoint = (moved_to or since or started).strftime(_TIME)
        return FetchResult(
            tuple(found.records.values()),
            limit_rejected(found.rejected),
            new_checkpoint,
            new_checkpoint,
            partial=True,
            more=cut,
        )

    def _read_changed(
        self, api: NvdApiClient, since: datetime, now: datetime, wanted: set[str], found: _Collected
    ) -> datetime | None:
        """Reads the wanted CVEs changed since `since`; the end of the window when all its pages were read."""
        end = min(now, since + timedelta(days=IntelLimits.NVD_MAX_WINDOW_DAYS))
        if end <= since:  # a checkpoint from the future (clock skew): nothing to ask yet
            return since
        index = 0
        while True:
            window = {"lastModStartDate": since.strftime(_TIME), "lastModEndDate": end.strftime(_TIME)}
            body = api.get({**window, "startIndex": index, "resultsPerPage": IntelLimits.NVD_PAGE_SIZE})
            if body is None:
                return None
            items, total = body["vulnerabilities"], body.get("totalResults")
            self._collect(items, wanted, found)
            index += len(items)
            if not items or not isinstance(total, int) or index >= total:
                return end

    def _collect(self, items: list[Any], wanted: set[str], found: _Collected) -> None:
        for item in items:
            cve = item.get("cve") if isinstance(item, dict) else None
            cve_id = cve.get("id") if isinstance(cve, dict) else None
            if isinstance(cve_id, str) and cve_id.upper() not in wanted:
                continue  # a window lists every CVE NVD changed: only ours are read
            made = self._reader.read_item(item)
            if isinstance(made, IntelRecord):
                found.records[made.external_id] = made
            else:
                found.rejected.append(made)


def _parse_time(checkpoint: str | None) -> datetime | None:
    """The saved checkpoint as a time; anything else (first run, a hand-edited value) starts a first pass."""
    try:
        return datetime.fromisoformat(checkpoint).astimezone(UTC) if checkpoint else None
    except ValueError:
        return None
