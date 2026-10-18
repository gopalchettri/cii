"""The six approved sources, built in the order they must run (KEV before EPSS and NVD, which read its CVE
ids; NVD last, the slowest), and the one method every source offers the refresh."""

from typing import Protocol

from app.core.constants import IntelSource
from app.data_access.external_intelligence.intel_record_repository import IntelRecordRepository
from app.models.external_intelligence.fetch_result import FetchResult
from app.worker.external_intelligence.record_batch_writer import list_current_external_ids
from app.worker.external_intelligence.sources.cisa_ics_advisories_source import CisaIcsAdvisoriesSource
from app.worker.external_intelligence.sources.cisa_known_exploited_source import CisaKnownExploitedSource
from app.worker.external_intelligence.sources.first_epss_scores_source import FirstEpssScoresSource
from app.worker.external_intelligence.sources.http_download import HttpDownloader
from app.worker.external_intelligence.sources.mitre_attack_source import MitreAttackSource
from app.worker.external_intelligence.sources.nist_nvd_details_source import NistNvdDetailsSource


class IntelSourceFetcher(Protocol):
    """What every source class offers the refresh."""

    source_id: IntelSource

    def download_changes(self, checkpoint: str | None) -> FetchResult | None:
        """The source's records since `checkpoint` (None: the first run, everything); None when the source
        has nothing new. Raises IntelFetchFailed when it cannot be read."""
        ...


class SourceCatalogue:
    """Builds the sources' fetchers over one record store."""

    def __init__(self, record_store: IntelRecordRepository, downloader: HttpDownloader | None = None) -> None:
        self._store = record_store
        self._downloader = downloader

    def fetchers(self) -> dict[IntelSource, IntelSourceFetcher]:
        """A fresh fetcher per source, in running order. Each reads the CVE ids it needs from the store when
        it runs, never when it is built."""
        store, web = self._store, self._downloader
        ordered: list[IntelSourceFetcher] = [
            CisaKnownExploitedSource(web),
            MitreAttackSource(IntelSource.ATTACK_ENTERPRISE, web),
            MitreAttackSource(IntelSource.ATTACK_ICS, web),
            CisaIcsAdvisoriesSource(web),
            FirstEpssScoresSource(lambda: list_current_external_ids(store, IntelSource.CISA_KEV), web),
            NistNvdDetailsSource(
                lambda: list_current_external_ids(store, IntelSource.CISA_KEV),
                lambda: list_current_external_ids(store, IntelSource.NIST_NVD),
            ),
        ]
        return {fetcher.source_id: fetcher for fetcher in ordered}
