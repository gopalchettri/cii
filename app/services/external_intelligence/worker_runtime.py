"""The composition the worker needs and may not build itself (the worker layer imports no service):
loaded with the worker's task modules (app/worker/celery_app.py TASK_MODULES), it installs the run-time
switch and the source refresher in the worker's IntelAccess. Providers only: nothing is built or read
until first used."""

from app.core.database import get_mongodb
from app.data_access.external_intelligence.feed_status_store import FeedStatusStore
from app.data_access.external_intelligence.intel_record_store import IntelRecordStore
from app.search.external_intelligence.index_keeper import get_evidence_index_keeper
from app.services.external_intelligence.refresh_sources import SourceRefresher
from app.services.external_intelligence.sources.source_catalogue import SourceCatalogue
from app.services.external_intelligence.switch import get_external_intelligence_switch
from app.worker.external_intelligence.intel_access import get_intel_access
from app.worker.external_intelligence.intel_runtime import IntelRuntime


def build_source_refresher() -> SourceRefresher:
    db = get_mongodb()
    records = IntelRecordStore(db)
    return SourceRefresher(
        SourceCatalogue(records), records, FeedStatusStore(db), get_evidence_index_keeper()
    )


get_intel_access().install(IntelRuntime(get_external_intelligence_switch, build_source_refresher))
