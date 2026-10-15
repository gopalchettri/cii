"""CISA ICS advisories (OT) from the CSAF 2.0 repository. `changes.csv` lists every advisory file with its
it last changed; a run downloads only the files changed after the saved checkpoint, oldest first, at most
ICS_MAX_PER_RUN of them. The result is always `partial` (incremental): what is absent is not retired.

A file that fails to download is NEVER skipped silently. The checkpoint (format in ics_checkpoint.py) advances
only to the last change time BEFORE the first failed file, so the next run reads that file again. To keep one
permanently missing file from holding the checkpoint for ever, the checkpoint also counts, per failed file,
the runs it has failed in: from the third run on the file is rejected (ICS_DOWNLOAD_FAILED) and no longer
blocks. A failure counts only in a run in which another file did download (the host is up, this file is the
problem); a run in which nothing downloaded is a host failure: it raises and changes no count."""

import csv
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import groupby
from typing import Final

from app.core.constants import (
    IcsReading,
    IntelLimits,
    IntelMessage,
    IntelRejection,
    IntelSource,
    IntelUrl,
    SourceDownload,
)
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of
from app.services.external_intelligence.sources.bounded_parse import load_json, within_parse_limit
from app.services.external_intelligence.sources.http_download import HttpDownloader
from app.services.external_intelligence.sources.ics_advisory_reader import IcsAdvisoryReader
from app.services.external_intelligence.sources.ics_checkpoint import (
    format_checkpoint,
    is_past,
    parse_checkpoint,
)
from app.services.external_intelligence.sources.text_guard import (
    SourceTextGuard,
    UnsafeSourceText,
    limit_rejected,
    plain_id,
    sort_into,
)

_PATH = re.compile(r"\d{4}/[\w.-]+\.json")
_STAMP_FORMAT: Final = "%Y-%m-%dT%H:%M:%S.%fZ"
_DAYS_PER_MONTH: Final = 30.4375
Change = tuple[str, str]  # (change time, path)


class _Run:
    """What one run read so far (local to one call, never shared)."""

    def __init__(self) -> None:
        self.records: list[IntelRecord] = []
        self.rejected: list[RejectedRecord] = []
        self.processed: list[Change] = []
        self.failed: list[Change] = []
        self.successes = 0
        self.stopped = False  # the host failed too many times in a row: the rest is left for the next run


class CisaIcsAdvisoriesSource:
    source_id = IntelSource.CISA_ICS

    def __init__(
        self, downloader: HttpDownloader | None = None, clock: Callable[[], datetime] | None = None
    ) -> None:
        self._downloader = downloader or HttpDownloader()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._guard = SourceTextGuard(IntelSource.CISA_ICS)
        self._reader = IcsAdvisoryReader(self._guard)

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The advisories changed after `checkpoint` (a first run: in the last ICS_FIRST_RUN_MONTHS), or None
        when none changed."""
        now = self._clock()
        stamp, failed_runs = parse_checkpoint(checkpoint, now)
        floor = stamp or _first_run_floor(now)
        with self._downloader.batch() as web:
            listing = _listing(web.download(IntelUrl.ICS_CHANGES, SourceDownload.MAX_ICS_CHANGES_BYTES), now)
            changed, more = _select(listing, floor)
            if not changed:
                return None
            run = self._read_files(web, changed)
        return self._result(run, changed, (floor, failed_runs), more)

    def _read_files(self, web: HttpDownloader, changed: list[Change]) -> _Run:
        run = _Run()
        streak = 0
        for item in changed:
            body = _load(web, item[1])
            run.processed.append(item)
            if body is None:
                run.failed.append(item)
                streak += 1
                if streak >= IntelLimits.ICS_MAX_CONSECUTIVE_FAILURES:
                    run.stopped = True
                    break
                continue
            streak = 0
            run.successes += 1
            made = self._read_file(item[1], body)
            sort_into(made, run.records, run.rejected)
        return run

    def _result(
        self, run: _Run, changed: list[Change], previous: tuple[str, dict[str, int]], more: bool
    ) -> FetchResult:
        floor, failed_runs = previous
        if run.failed and not run.successes:
            raise IntelFetchFailed(IntelMessage.ICS_UNREACHABLE, url=IntelUrl.ICS_CSAF, count=len(run.failed))
        blocking, failed_now = self._count_failures(run, failed_runs)
        # Nothing at or after the first failed file, or the first file left unread, counts as done.
        barriers = [stamp for stamp, _ in blocking] + [
            stamp for stamp, _ in changed[len(run.processed) :][:1]
        ]
        barrier = min(barriers, default=None)
        done = [stamp for stamp, _ in run.processed if barrier is None or stamp < barrier]
        new_stamp = max(done, default=floor)
        read_paths = {path for _, path in run.processed}
        remembered = {path: runs for path, runs in failed_runs.items() if path not in read_paths}
        checkpoint = format_checkpoint(new_stamp, {**remembered, **failed_now})
        return FetchResult(
            tuple(run.records),
            limit_rejected(run.rejected),
            checkpoint,
            new_stamp,
            partial=True,
            more=more and barrier is None,
        )

    def _count_failures(self, run: _Run, failed_runs: dict[str, int]) -> tuple[list[Change], dict[str, int]]:
        """The failed files that still block the checkpoint, with their failed-run counts; a file that failed
        in too many runs is rejected here instead."""
        blocking: list[Change] = []
        counts: dict[str, int] = {}
        for stamp, path in run.failed:
            runs = failed_runs.get(path, 0) + 1
            if runs >= IcsReading.MAX_FAILED_RUNS:
                name = plain_id(path.rpartition("/")[2].removesuffix(".json").upper())
                run.rejected.append(
                    RejectedRecord(
                        IntelSource.CISA_ICS, name, IntelRejection.ICS_DOWNLOAD_FAILED, content_hash_of(path)
                    )
                )
            else:
                blocking.append((stamp, path))
                counts[path] = runs
        return blocking, counts

    def _read_file(self, path: str, body: bytes) -> IntelRecord | RejectedRecord:
        """One advisory file as a record; an unreadable or incomplete one as a rejected one, an unsafe one as
        a quarantined one."""
        name = plain_id(path.rpartition("/")[2].removesuffix(".json").upper())
        try:
            doc = load_json(body, IntelSource.CISA_ICS.value)
            made = self._reader.read_advisory(doc, path) if isinstance(doc, dict) else None
        except UnsafeSourceText as unsafe:
            return self._guard.quarantine(name, path, unsafe.reason)
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError, IntelFetchFailed):
            made = None  # a malformed file is rejected, never a failed run
        if made is not None:
            return made
        return RejectedRecord(
            IntelSource.CISA_ICS,
            name,
            IntelRejection.ICS_BAD_ADVISORY,
            content_hash_of(path, body.decode("utf-8", "replace")),
        )


def _listing(body: bytes, now: datetime) -> dict[str, str]:
    """path -> latest change time, from the rows of changes.csv that look right. A change time after `now`
    is not a change time (a clock that is wrong, or a hostile file): it must never become the checkpoint."""
    rows: dict[str, str] = {}
    for row in csv.reader(
        within_parse_limit(body, IntelSource.CISA_ICS.value).decode("utf-8-sig", "replace").splitlines()
    ):
        if len(row) == 2 and _PATH.fullmatch(row[0]) and is_past(row[1], now):
            rows[row[0]] = max(row[1], rows.get(row[0], ""))
    if not rows:
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.CISA_ICS.value)
    return rows


def _select(rows: dict[str, str], floor: str) -> tuple[list[Change], bool]:
    """(change time, path) oldest first, those after `floor`, cut at the per-run cap on a change-time
    boundary so that the checkpoint never skips a file that shares its time. Also whether more remain."""
    newer = sorted((stamp, path) for path, stamp in rows.items() if stamp > floor)
    taken: list[Change] = []
    for _, same_time in groupby(newer, key=lambda item: item[0]):
        batch = list(same_time)
        if taken and len(taken) + len(batch) > IntelLimits.ICS_MAX_PER_RUN:
            break
        taken += batch
    return taken, len(taken) < len(newer)


def _first_run_floor(now: datetime) -> str:
    days = round(IntelLimits.ICS_FIRST_RUN_MONTHS * _DAYS_PER_MONTH)
    return (now - timedelta(days=days)).strftime(_STAMP_FORMAT)


def _load(web: HttpDownloader, path: str) -> bytes | None:
    try:
        return web.download(IntelUrl.ICS_CSAF + path, SourceDownload.MAX_ICS_FILE_BYTES)
    except IntelFetchFailed:
        return None
