"""Installs the run-time switch and the source refresher in the worker's IntelAccess (the worker layer may not
import services); loaded with the worker's task modules, it builds nothing until first used."""

from app.data_access.external_intelligence.repository import intel_feeds, intel_records
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.services.external_intelligence.refresh_sources import SourceRefresher
from app.services.external_intelligence.sources.source_catalogue import SourceCatalogue
from app.services.external_intelligence.switch import get_external_intelligence_switch
from app.worker.external_intelligence.intel_access import get_intel_access


def build_source_refresher() -> SourceRefresher:
    """A source refresher over the process's stores and evidence index keeper."""
    return SourceRefresher(
        SourceCatalogue(intel_records), intel_records, intel_feeds, get_evidence_index_keeper()
    )


get_intel_access().install(get_external_intelligence_switch, build_source_refresher)
