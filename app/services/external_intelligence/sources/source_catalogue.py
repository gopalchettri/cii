"""The six approved sources, built in the order they must run: KEV before EPSS and NVD (both read the KEV CVE
ids from the record store), NVD last (it is the slowest, paced to the API limit)."""

from app.core.constants import IntelSource
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.services.external_intelligence.sources.cisa_ics_advisories_source import CisaIcsAdvisoriesSource
from app.services.external_intelligence.sources.cisa_known_exploited_source import CisaKnownExploitedSource
from app.services.external_intelligence.sources.first_epss_scores_source import FirstEpssScoresSource
from app.services.external_intelligence.sources.http_download import HttpDownloader
from app.services.external_intelligence.sources.mitre_attack_source import MitreAttackSource
from app.services.external_intelligence.sources.nist_nvd_details_source import NistNvdDetailsSource
from app.services.external_intelligence.sources.source_fetcher import IntelSourceFetcher


class SourceCatalogue:
    def __init__(self, record_store: IntelRecordStore, downloader: HttpDownloader | None = None) -> None:
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
            FirstEpssScoresSource(lambda: store.list_current_external_ids(IntelSource.CISA_KEV), web),
            NistNvdDetailsSource(
                lambda: store.list_current_external_ids(IntelSource.CISA_KEV),
                lambda: store.list_current_external_ids(IntelSource.NIST_NVD),
            ),
        ]
        return {fetcher.source_id: fetcher for fetcher in ordered}
