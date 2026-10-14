"""FIRST EPSS: one EXPLOIT_SCORE record per CVE the caller knows, read as a stream (about 250k rows, not held
as a list). The scores are joined to the KEV vulnerabilities, so every other CVE is dropped before it is
parsed.

Checkpoint: `<score date>|<12 hex of the hash of the CVEs asked for>`. A CVE KEV gained since the last run
changes the second part, so its score is fetched today instead of at the next score date. Every value the
record says is a number or a validated date or CVE id: the file carries no free text, so nothing here needs
the sanitiser (and nothing in it could carry a sentence)."""

import csv
import io
import re
from collections.abc import Callable, Iterator

from app.core.constants import (
    AssetType,
    EpssReading,
    IntelKind,
    IntelLimits,
    IntelMessage,
    IntelRejection,
    IntelSource,
    IntelUrl,
)
from app.core.exceptions import IntelFetchFailed
from app.models.external_intelligence.fetch_result import FetchResult
from app.models.external_intelligence.intel_record import IntelRecord, RejectedRecord, content_hash_of
from app.services.external_intelligence.sources.bounded_parse import open_gzip_text
from app.services.external_intelligence.sources.http_download import HttpDownloader

_COLUMNS = ("cve", "epss", "percentile")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_SCORE_DATE = re.compile(r"\d{4}-\d{2}-\d{2}(?:T[\d:.]+Z)?")
_NVD_PAGE = "https://nvd.nist.gov/vuln/detail/{cve}"


class FirstEpssScoresSource:
    source_id = IntelSource.FIRST_EPSS

    def __init__(self, known_cves: Callable[[], set[str]], downloader: HttpDownloader | None = None) -> None:
        self._known_cves = known_cves
        self._downloader = downloader or HttpDownloader()

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The scores of the known CVEs, or None when there are none or nothing changed since `checkpoint`."""
        wanted = {cve.upper() for cve in self._known_cves()}
        if not wanted:
            return None
        body = self._downloader.download(IntelUrl.FIRST_EPSS)
        records: list[IntelRecord] = []
        rejected: list[RejectedRecord] = []
        try:
            with open_gzip_text(body, IntelSource.FIRST_EPSS) as lines:
                score_date = _score_date(lines.readline(EpssReading.FIRST_LINE_BYTES))
                marker = f"{score_date}|{content_hash_of(sorted(wanted))[: EpssReading.MARKER_HEX_CHARS]}"
                if marker == checkpoint:
                    return None
                for row in _rows(lines):
                    if row and row[0].strip().upper() in wanted:
                        _add(row, score_date, records, rejected)
        except (OSError, EOFError, UnicodeError, csv.Error):  # corrupt gzip, truncated stream, bad bytes
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.FIRST_EPSS) from None
        return FetchResult(tuple(records), tuple(rejected), marker, score_date)


def _score_date(first_line: str) -> str:
    """`#model_version:v2025.03.14,score_date:2026-10-12T00:00:00Z` -> the score_date value."""
    pairs = dict(part.partition(":")[::2] for part in first_line.lstrip("#").strip().split(","))
    date = pairs.get("score_date", "")
    complete = first_line.endswith("\n") and len(first_line) < EpssReading.FIRST_LINE_BYTES
    if not (complete and first_line.startswith("#") and _SCORE_DATE.fullmatch(date)):
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.FIRST_EPSS)
    return date


def _rows(lines: io.TextIOWrapper) -> Iterator[list[str]]:
    """The data rows after the header line; a header other than cve,epss,percentile is a bad format."""
    reader = csv.reader(lines)
    if tuple(next(reader, ())) != _COLUMNS:
        raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.FIRST_EPSS)
    for count, row in enumerate(reader, start=1):
        if count > EpssReading.MAX_ROWS:
            raise IntelFetchFailed(IntelMessage.BAD_FORMAT, source=IntelSource.FIRST_EPSS)
        yield row


def _add(row: list[str], score_date: str, records: list[IntelRecord], rejected: list[RejectedRecord]) -> None:
    cve = row[0].strip().upper()
    scores = _scores(row) if len(row) == len(_COLUMNS) and _CVE.fullmatch(cve) else None
    if scores is None:
        reason = IntelRejection.EPSS_BAD_ROW if len(row) != len(_COLUMNS) else IntelRejection.EPSS_BAD_SCORE
        if len(rejected) < IntelLimits.MAX_REJECTED_PER_RUN:
            rejected.append(RejectedRecord(IntelSource.FIRST_EPSS, "", reason, content_hash_of(row)))
        return
    epss, percentile = scores
    day = score_date[:10]
    data = {"cve": cve, "epss": epss, "percentile": percentile, "score_date": day}
    text = f"{cve} EPSS {cve}. Exploit prediction score {epss}, percentile {percentile}, on {day}."
    records.append(
        IntelRecord(
            IntelSource.FIRST_EPSS,
            cve,
            IntelKind.EXPLOIT_SCORE,
            AssetType.IT.value,
            cve,
            text,
            _NVD_PAGE.format(cve=cve),
            score_date,
            data=data,
        )
    )


def _scores(row: list[str]) -> tuple[float, float] | None:
    try:
        epss, percentile = float(row[1]), float(row[2])
    except ValueError:
        return None
    return (epss, percentile) if 0.0 <= epss <= 1.0 and 0.0 <= percentile <= 1.0 else None  # False for nan
